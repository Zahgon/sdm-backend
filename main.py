# pylint: disable=unused-import

import argparse
import binascii
import io
from typing import Optional

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

from config import (
    CTR_PARAM,
    ENC_FILE_DATA_PARAM,
    ENC_PICC_DATA_PARAM,
    REQUIRE_LRP,
    SDMMAC_PARAM,
    MASTER_KEY,
    UID_PARAM,
    DERIVE_MODE,
)

if DERIVE_MODE == "legacy":
    from libsdm.legacy_derive import derive_tag_key, derive_undiversified_key
elif DERIVE_MODE == "standard":
    from libsdm.derive import derive_tag_key, derive_undiversified_key
else:
    raise RuntimeError("Invalid DERIVE_MODE.")

from libsdm.sdm import (
    EncMode,
    InvalidMessage,
    ParamMode,
    decrypt_sun_message,
    validate_plain_sun,
)

app = FastAPI(title="SDM Backend")
templates = Jinja2Templates(directory="templates")


def get_demo_mode() -> bool:
    """Check if running in demo mode (all-zeros master key)."""
    return MASTER_KEY == (b"\x00" * 16)


@app.exception_handler(400)
async def handler_bad_request(request: Request, exc: HTTPException):
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "code": 400, "msg": str(exc.detail), "demo_mode": get_demo_mode()},
        status_code=400
    )


@app.exception_handler(403)
async def handler_forbidden(request: Request, exc: HTTPException):
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "code": 403, "msg": str(exc.detail), "demo_mode": get_demo_mode()},
        status_code=403
    )


@app.exception_handler(404)
async def handler_not_found(request: Request, exc: HTTPException):
    return templates.TemplateResponse(
        "error.html",
        {"request": request, "code": 404, "msg": str(exc.detail), "demo_mode": get_demo_mode()},
        status_code=404
    )


@app.get('/', response_class=HTMLResponse)
async def sdm_main(request: Request):
    """
    Main page with a few examples.
    """
    return templates.TemplateResponse(
        "sdm_main.html",
        {"request": request, "demo_mode": get_demo_mode()}
    )


# pylint:  disable=too-many-branches
def parse_parameters(request: Request):
    arg_e = request.query_params.get('e')
    if arg_e:
        param_mode = ParamMode.BULK

        try:
            e_b = binascii.unhexlify(arg_e)
        except binascii.Error:
            raise HTTPException(status_code=400, detail="Failed to decode parameters.")

        e_buf = io.BytesIO(e_b)

        if (len(e_b) - 8) % 16 == 0:
            # using AES (16 byte PICCEncData)
            file_len = len(e_b) - 16 - 8
            enc_picc_data_b = e_buf.read(16)

            if file_len > 0:
                enc_file_data_b = e_buf.read(file_len)
            else:
                enc_file_data_b = None

            sdmmac_b = e_buf.read(8)
        elif (len(e_b) - 8) % 16 == 8:
            # using LRP (24 byte PICCEncData)
            file_len = len(e_b) - 24 - 8
            enc_picc_data_b = e_buf.read(24)

            if file_len > 0:
                enc_file_data_b = e_buf.read(file_len)
            else:
                enc_file_data_b = None

            sdmmac_b = e_buf.read(8)
        else:
            raise HTTPException(status_code=400, detail="Incorrect length of the dynamic parameter.")
    else:
        param_mode = ParamMode.SEPARATED
        enc_picc_data = request.query_params.get(ENC_PICC_DATA_PARAM)
        enc_file_data = request.query_params.get(ENC_FILE_DATA_PARAM)
        sdmmac = request.query_params.get(SDMMAC_PARAM)

        if not enc_picc_data:
            raise HTTPException(status_code=400, detail=f"Parameter {ENC_PICC_DATA_PARAM} is required")

        if not sdmmac:
            raise HTTPException(status_code=400, detail=f"Parameter {SDMMAC_PARAM} is required")

        try:
            enc_file_data_b = None
            enc_picc_data_b = binascii.unhexlify(enc_picc_data)
            sdmmac_b = binascii.unhexlify(sdmmac)

            if enc_file_data:
                enc_file_data_b = binascii.unhexlify(enc_file_data)
        except binascii.Error:
            raise HTTPException(status_code=400, detail="Failed to decode parameters.")

    return param_mode, enc_picc_data_b, enc_file_data_b, sdmmac_b


@app.get('/tagpt', response_class=HTMLResponse)
async def sdm_info_plain(request: Request):
    """
    Return HTML
    """
    return _internal_tagpt(request)


@app.get('/api/tagpt')
async def sdm_api_info_plain(request: Request):
    """
    Return JSON
    """
    try:
        return _internal_tagpt(request, force_json=True)
    except HTTPException as err:
        return JSONResponse({"error": str(err.detail)}, status_code=400)


def _internal_tagpt(request: Request, force_json: bool = False):
    try:
        uid = binascii.unhexlify(request.query_params[UID_PARAM])
        read_ctr = binascii.unhexlify(request.query_params[CTR_PARAM])
        cmac = binascii.unhexlify(request.query_params[SDMMAC_PARAM])
    except (binascii.Error, KeyError):
        raise HTTPException(status_code=400, detail="Failed to decode parameters.")

    try:
        sdm_file_read_key = derive_tag_key(MASTER_KEY, uid, 2)
        res = validate_plain_sun(uid=uid,
                                 read_ctr=read_ctr,
                                 sdmmac=cmac,
                                 sdm_file_read_key=sdm_file_read_key)
    except InvalidMessage:
        raise HTTPException(status_code=400, detail="Invalid message (most probably wrong signature).")

    if REQUIRE_LRP and res['encryption_mode'] != EncMode.LRP:
        raise HTTPException(status_code=400, detail="Invalid encryption mode, expected LRP.")

    if request.query_params.get("output") == "json" or force_json:
        return JSONResponse({
            "uid": res['uid'].hex().upper(),
            "read_ctr": res['read_ctr'],
            "enc_mode": res['encryption_mode'].name
        })

    return templates.TemplateResponse(
        'sdm_info.html',
        {
            "request": request,
            "demo_mode": get_demo_mode(),
            "encryption_mode": res['encryption_mode'].name,
            "uid": res['uid'],
            "read_ctr_num": res['read_ctr']
        }
    )


@app.get('/webnfc', response_class=HTMLResponse)
async def sdm_webnfc(request: Request):
    return templates.TemplateResponse(
        'sdm_webnfc.html',
        {"request": request, "demo_mode": get_demo_mode()}
    )


@app.get('/tagtt', response_class=HTMLResponse)
async def sdm_info_tt(request: Request):
    return _internal_sdm(request, with_tt=True)


@app.get('/api/tagtt')
async def sdm_api_info_tt(request: Request):
    try:
        return _internal_sdm(request, with_tt=True, force_json=True)
    except HTTPException as err:
        return JSONResponse({"error": str(err.detail)})


@app.get('/tag', response_class=HTMLResponse)
async def sdm_info(request: Request):
    return _internal_sdm(request, with_tt=False)


@app.get('/api/tag')
async def sdm_api_info(request: Request):
    try:
        return _internal_sdm(request, with_tt=False, force_json=True)
    except HTTPException as err:
        return JSONResponse({"error": str(err.detail)})


# pylint:  disable=too-many-branches, too-many-statements, too-many-locals
def _internal_sdm(request: Request, with_tt: bool = False, force_json: bool = False):
    """
    SUN decrypting/validating endpoint.
    """
    param_mode, enc_picc_data_b, enc_file_data_b, sdmmac_b = parse_parameters(request)

    try:
        res = decrypt_sun_message(param_mode=param_mode,
                                  sdm_meta_read_key=derive_undiversified_key(MASTER_KEY, 1),
                                  sdm_file_read_key=lambda uid: derive_tag_key(MASTER_KEY, uid, 2),
                                  picc_enc_data=enc_picc_data_b,
                                  sdmmac=sdmmac_b,
                                  enc_file_data=enc_file_data_b)
    except InvalidMessage:
        raise HTTPException(status_code=400, detail="Invalid message (most probably wrong signature).")

    if REQUIRE_LRP and res['encryption_mode'] != EncMode.LRP:
        raise HTTPException(status_code=400, detail="Invalid encryption mode, expected LRP.")

    picc_data_tag = res['picc_data_tag']
    uid = res['uid']
    read_ctr_num = res['read_ctr']
    file_data = res['file_data']
    encryption_mode = res['encryption_mode'].name

    file_data_utf8 = ""
    tt_status_api = ""
    tt_status = ""
    tt_color = ""

    if res['file_data']:
        if param_mode == ParamMode.BULK:
            file_data_len = file_data[2]
            file_data_unpacked = file_data[3:3 + file_data_len]
        else:
            file_data_unpacked = file_data

        file_data_utf8 = file_data_unpacked.decode('utf-8', 'ignore')

        if with_tt:
            tt_perm_status = file_data[0:1].decode('ascii', 'replace')
            tt_cur_status = file_data[1:2].decode('ascii', 'replace')

            if tt_perm_status == 'C' and tt_cur_status == 'C':
                tt_status_api = 'secure'
                tt_status = 'OK (not tampered)'
                tt_color = 'green'
            elif tt_perm_status == 'O' and tt_cur_status == 'C':
                tt_status_api = 'tampered_closed'
                tt_status = 'Tampered! (loop closed)'
                tt_color = 'red'
            elif tt_perm_status == 'O' and tt_cur_status == 'O':
                tt_status_api = 'tampered_open'
                tt_status = 'Tampered! (loop open)'
                tt_color = 'red'
            elif tt_perm_status == 'I' and tt_cur_status == 'I':
                tt_status_api = 'not_initialized'
                tt_status = 'Not initialized'
                tt_color = 'orange'
            elif tt_perm_status == 'N' and tt_cur_status == 'T':
                tt_status_api = 'not_supported'
                tt_status = 'Not supported by the tag'
                tt_color = 'orange'
            else:
                tt_status_api = 'unknown'
                tt_status = 'Unknown'
                tt_color = 'orange'

    if request.query_params.get("output") == "json" or force_json:
        return JSONResponse({
            "uid": uid.hex().upper(),
            "file_data": file_data.hex() if file_data else None,
            "read_ctr": read_ctr_num,
            "tt_status": tt_status_api,
            "enc_mode": encryption_mode
        })

    return templates.TemplateResponse(
        'sdm_info.html',
        {
            "request": request,
            "demo_mode": get_demo_mode(),
            "encryption_mode": encryption_mode,
            "picc_data_tag": picc_data_tag,
            "uid": uid,
            "read_ctr_num": read_ctr_num,
            "file_data": file_data,
            "file_data_utf8": file_data_utf8,
            "tt_status": tt_status,
            "tt_color": tt_color
        }
    )


if __name__ == '__main__':
    import uvicorn
    parser = argparse.ArgumentParser(description='OTA NFC Server')
    parser.add_argument('--host', type=str, nargs='?', default='127.0.0.1', help='address to listen on')
    parser.add_argument('--port', type=int, nargs='?', default=5000, help='port to listen on')

    args = parser.parse_args()

    uvicorn.run(app, host=args.host, port=args.port)
