from pyzbar.pyzbar import decode
from PIL import Image

def decode_qr_from_image(image_path):
    try:
        img = Image.open(image_path)
        decoded = decode(img)
        if decoded:
            return decoded[0].data.decode('utf-8')
        return None
    except Exception as e:
        print(f"QR decode error: {e}")
        return None