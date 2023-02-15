from flask import Flask, render_template, request, flash
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import base64
import secrets

app = Flask(__name__)
app.secret_key = "cryptography"

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/encrypt")
def encrypt():
    return render_template("encrypt.html")

@app.route("/encrypt_message", methods=["POST"])
def encrypt_message():
    if request.method == 'POST':
        message = request.form['message'].encode('utf-8')
        #password = request.form['password'].encode('utf-8')
        key = secrets.token_bytes(16)
        iv = b'0123456789abcdef'
        padded_message = pad(message, 16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ciphertext = base64.b64encode(cipher.encrypt(padded_message)).decode('utf-8')
        return render_template('encryptedmessage.html', ciphertext=ciphertext, key=base64.b64encode(key).decode('utf-8'))
    else:
        flash("Something Went Wrong")
        return render_template('encrypt.html')

@app.route("/decrypt")
def decrypt():
    return render_template("decrypt.html")

@app.route("/decryptedmessage", methods=["POST"])
def decryptedmessage():
    if request.method == "POST":
        ciphertext = request.form['message']
        # Decode the base64-encoded key
        key = base64.b64decode(request.form['key'])
        iv = b'0123456789abcdef'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        # Decrypt the ciphertext and remove the padding
        decrypted_message = unpad(cipher.decrypt(base64.b64decode(ciphertext)), 16).decode('utf-8')
        return render_template("decryptedmessage.html", decrypttext=decrypted_message)
    else:
        flash("Something went wrong!")
        return render_template("decrypt.html")
if __name__ == "__main__":
    app.run(debug=True)