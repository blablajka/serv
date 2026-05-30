import json

with open('d:/web_panel_for_vpn/smart_vpn/panel/main.py', 'r', encoding='utf-8') as f:
    content = f.read()

new_endpoints = '''
@app.get("/api/settings")
async def get_settings(username: str = Depends(verify_credentials)):
    db = load_clients_db()
    return db.get("__global__", {})

@app.post("/api/settings")
async def update_settings(payload: dict, username: str = Depends(verify_credentials)):
    db = load_clients_db()
    if "__global__" not in db:
        db["__global__"] = {}
    
    # Update only allowed fields
    allowed_fields = ["domain", "xhttp_path", "reality_server_names"]
    for k, v in payload.items():
        if k in allowed_fields:
            if k == "reality_server_names" and isinstance(v, str):
                db["__global__"][k] = [v.strip()]
            else:
                db["__global__"][k] = v
                
    save_clients_db(db)
    
    # Re-generate configs and restart xray
    try:
        from config_generator import generate_xray_config
        generate_xray_config(db)
        import os
        os.system("systemctl restart xray")
        return {"status": "ok", "message": "Settings updated and Xray restarted"}
    except Exception as e:
        logger.error(f"Error applying settings: {e}")
        from fastapi.responses import JSONResponse
        return JSONResponse(content={"error": str(e)}, status_code=500)
'''

pos = content.find('@app.get("/api/diagnostics/logs")')
if pos != -1:
    content = content[:pos] + new_endpoints + '\n' + content[pos:]
    with open('d:/web_panel_for_vpn/smart_vpn/panel/main.py', 'w', encoding='utf-8') as f:
        f.write(content)
    print('main.py updated successfully')
else:
    print('Failed to find insertion point')
