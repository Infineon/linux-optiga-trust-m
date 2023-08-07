import binascii
import csv
import os
import secrets
import string
import uuid

import optigatrust as optiga
import qrcode
from optigatrust import objects, port
from PIL import Image, ImageDraw, ImageFont
import RPi.GPIO as GPIO
import time 

## Transport-Key Alphabet
ambiguous_chars = [',', 'l', 'I', 'O', '0', '1', '"', '`', '´', '|', '°']
alphabet = (string.ascii_letters + string.digits + string.punctuation)
for char in ambiguous_chars:
    alphabet = alphabet.replace(char, '')

def generate_guid():
    return str(uuid.uuid4())

def generate_transportKey():
    return ''.join(secrets.choice(alphabet) for i in range(15)).strip()
    
def get_chipID():
    uid_obj = optiga.Object(0xe0c2)
    # Get only needed part form the UID (batch number and the X,Y coordinates)
    # and convert it into an uppercase hex string
    return binascii.hexlify(uid_obj.read()[11:21]).decode('utf-8').upper()

def try_optiga():
    cert_ecc = objects.X509(0xe0e0).pem.decode()

def print_label(batchID, boardID, transportKey):
    text_begin = 0.05
    offset = 0.05
    line_distance = 0.15
    x_y_scale = 3.1
    output_y_res = 236
    font_size = 0.105
    qr = qrcode.make(""+batchID)
    x,y = qr.size
    img = Image.new('RGB', (int(x_y_scale*y), int(y)), color='white')
    font = ImageFont.truetype("arial.ttf", int(font_size*y))
    bold_font = ImageFont.truetype("arial_bold.ttf", int(font_size*1.2*y))

    d = ImageDraw.Draw(img)
    d.text((int(text_begin*y),int(offset*y)), "Batch-ID:", font=bold_font, fill='black')
    d.text((int(text_begin*y),int(offset*y+line_distance*y)), batchID, font=font, fill='black')
    d.text((int(text_begin*y),int(offset*y+2*line_distance*y)), "Board-ID:", font=bold_font, fill='black')
    d.text((int(text_begin*y),int(offset*y+3*line_distance*y)), boardID, font=font, fill='black')
    d.text((int(text_begin*y),int(offset*y+4*line_distance*y)), "Transport Key:", font=bold_font, fill='black')
    d.text((int(text_begin*y),int(offset*y+5*line_distance*y)), transportKey, font=font, fill='black')
    img.paste(qr, (int((x_y_scale-1)*y), 0))
    resize = img.resize((int(x_y_scale*output_y_res),output_y_res))
    resize.save("filler.png")
    # os.system("brother_ql -m QL-700 -b pyusb -p usb://0x04f9:2042 print -l 62 filler.png")
    # os.remove("filler.png")

if __name__ == '__main__':
    GPIO.setmode(GPIO.BCM)
    GPIO.setup(5, GPIO.OUT)
    GPIO.output(5, False)
    time.sleep(0.1)
    GPIO.output(5, True)
    row_dict = {"chipID": "", "batchID": "", "transportKey":""}
    with open("chip_list.csv", "a", newline='') as file:
        writer = csv.DictWriter(file, row_dict.keys())
        # Get the Certificate and Coprocessor Unique ID object handlers
        try:
            try_optiga()
            row_dict['chipID'] = get_chipID()
        except:
            try:
                try_optiga()
                row_dict['chipID'] = get_chipID()
            except Exception as e:
                print("Cannot connect to optiga.. exit!")
                exit(-1)
        print("Chip-ID: ", row_dict['chipID'])
        row_dict['batchID'] = generate_guid()
        row_dict['transportKey'] = generate_transportKey()
        writer.writerow(row_dict)
        print_label(row_dict['batchID'], row_dict['chipID'], row_dict['transportKey'])
    GPIO.cleanup()