from backend.app import app

# Expose Flask WSGI app as module-level variable `app`.
# Vercel's Python builder will import this module and serve the WSGI app.

# Keep file minimal — importing `app` is sufficient.

if __name__ == '__main__':
    # Allow local debugging if someone runs this file directly
    app.run(host='0.0.0.0', port=5000, debug=True)
