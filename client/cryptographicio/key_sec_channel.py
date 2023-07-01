from hashlib import sha1


def to_emojies(key):
    hashed = sha1(key).digest()
    emojies = "👻☠️👾👺💀🤡🐕‍🦺🐈‍⬛🦏🦬🐎🐆🐅🐄🐘🐀🦀🪸🦢🦉🐧🦋🦇🐝🐞🦂🕷️🕸️🦷🦴👀🫦🚴‍♀️🏋️🤸‍♂️🤞✌️🤜🎃🎄🎏🎗️🛝🖼️🎡🧵🪡🧶🪢👔🥼🥽👕🧣👠👢🎓🎩⚽💍💎🥇⛓️🧲⚔️🏹💿🔍🔦💡💴💵💶💷🍁"
    return "".join([emojies[int(b) % 64] for b in hashed][::4])
