import json

# Membaca file followers (orang yang follow kita)
f = open('D:/Adit/mahesa/instagram/keempat/followers_1.json')
data = json.load(f)
f.close()

followers = []
for i in data:
    for j in i["string_list_data"]:
        followers.append(j["value"])

# Membaca file following (orang yang kita follow)
f = open('D:/Adit/mahesa/instagram/keempat/following.json')
data = json.load(f)
f.close()

following = []
for i in data["relationships_following"]:
    for j in i["string_list_data"]:
        following.append(j["value"])

# Mencari akun yang follow kita, tetapi kita tidak follow balik
not_following_back = []

for i in followers:
    if i not in following:
        not_following_back.append(i)

# Menampilkan hasil
for i in not_following_back:
    print("https://www.instagram.com/" + i)
