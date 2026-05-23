from app.app import app

if __name__ == '__main__':
    print("[*] Starting Dash Server from root...")
    app.run(debug=False, port=8050)
