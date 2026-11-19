import re

with open("D:/Marathon-live/Marathon.exe", "rb") as f:
    text = f.read()

matches = [m.start() for m in re.finditer(b'"tasks"', text)]
print("tasks matches:", [hex(m) for m in matches])
for m in matches:
    print(text[max(0, m-50):m+150])
