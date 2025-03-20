PORT="${PORT:-8080}"


export FRONTEND_URL="http://localhost:5173"
export ENABLE_OAUTH_SIGNUP="true"

uvicorn open_webui.main:app --port $PORT --host 0.0.0.0 --forwarded-allow-ips '*' --reload
