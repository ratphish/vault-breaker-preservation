from PIL import Image

bmp_path = r"C:\Users\marra\AppData\Local\Temp\Marathon\crash_folder\crash_folder_5996_20261107_225412\bug_screenshot.bmp"
img = Image.open(bmp_path)
print("Image size:", img.size)

# Resize to 1280x720 and save as png to artifact directory or scratch
small = img.resize((1280, 720))
small.save(r"d:\vault-breaker-preservation\scripts\last_screenshot.png")
print("Saved 720p screenshot.")
