import shutil
import os, struct, zlib, tempfile, argparse
from tqdm import tqdm
from key import Keys


def readuint32(f):
    return struct.unpack('I', f.read(4))[0]


def readuint8(f):
    return struct.unpack('B', f.read(1))[0]


def get_ext(data):
    if len(data) == 0:
        return 'none'
    if data[:12] == b'CocosStudio-UI':
        return 'coc'
    elif data[:1] == b'<':
        return 'xml'
    elif data[:1] == b'{':
        return 'json'
    elif data[:3] == b'hit':
        return 'hit'
    elif data[:3] == b'PKM':
        return 'pkm'
    elif data[:3] == b'PVR':
        return 'pvr'
    elif data[:3] == b'DDS':
        return 'dds'
    elif data[1:4] == b'KTX':
        return 'ktx'
    elif data[1:4] == b'PNG':
        return 'png'
    elif data[:4] == bytes([0x34, 0x80, 0xC8, 0xBB]):
        return 'mesh'
    elif data[:4] == bytes([0x14, 0x00, 0x00, 0x00]):
        return 'type1'
    elif data[:4] == bytes([0x04, 0x00, 0x00, 0x00]):
        return 'type2'
    elif data[:4] == bytes([0x00, 0x01, 0x00, 0x00]):
        return 'type3'
    elif data[:4] == b'VANT':
        return 'vant'
    elif data[:4] == b'MDMP':
        return 'mdmp'
    elif data[:4] == b'RGIS':
        return 'gis'
    elif data[:4] == b'NTRK':
        return 'ntrk'
    elif data[:4] == b'RIFF':
        return 'riff'
    elif data[:4] == b'BKHD':
        return 'bnk'
    elif len(data) < 1000000:
        if b'void' in data or b'main(' in data or b'include' in data or b'float' in data:
            return 'shader'
        if b'technique' in data or b'ifndef' in data:
            return 'shader'
        if b'?xml' in data:
            return 'xml'
        if b'import' in data:
            return 'py'
        if b'1000' in data or b'ssh' in data or b'png' in data or b'tga' in data or b'exit' in data:
            return 'txt'
    return 'dat'


def unpack(path, statusBar=None):
    folder_path = path.replace('.npk', '')
    if not os.path.exists(folder_path):
        os.mkdir(folder_path)
    keys = Keys()

    with open(path, 'rb') as f:
        data = f.read(4)
        pkg_type = None
        if data == b'NXPK':
            pkg_type = 0
        elif data == b'EXPK':
            pkg_type = 1
        else:
            raise Exception('NOT NXPK/EXPK FILE')
        files = readuint32(f)
        var1 = readuint32(f)
        var2 = readuint32(f)
        var3 = readuint32(f)
        mode = 1 if var1 and var3 else 0
        info_size = 0x28 if mode else 0x1c
        index_offset = readuint32(f)
        f.seek(index_offset)
        index_table = []
        with tempfile.TemporaryFile() as tmp:
            data = f.read(files * 28)
            if pkg_type:
                data = keys.decrypt(data)
            tmp.write(data)
            tmp.seek(0)
            for _ in range(files):
                file_sign = readuint32(tmp)
                file_offset = readuint32(tmp)
                file_length = readuint32(tmp)
                file_original_length = readuint32(tmp)
                zcrc = readuint32(tmp)
                crc = readuint32(tmp)
                file_flag = readuint32(tmp)
                index_table.append((
                    file_sign,
                    file_offset,
                    file_length,
                    file_original_length,
                    crc,
                    file_flag,
                ))

        # === 性能优化：在循环外打开 manifest.txt 文件 ===
        manifest_path = os.path.join(folder_path, 'manifest.txt')
        with open(manifest_path, 'w', encoding='utf-8') as manifest:
            for i, item in enumerate(index_table):
                if i % 20 == 0 and statusBar != None:
                    statusBar.showMessage('{} / {}'.format(i, files))

                file_sign, file_offset, file_length, file_original_length, crc, file_flag = item
                f.seek(file_offset)
                data = f.read(file_length)
                if pkg_type:
                    data = keys.decrypt(data)

                zflag = file_flag & 0xFFFF  # zlib lz44
                file_flag = file_flag >> 16

                if file_flag == 3:
                    b = crc ^ file_original_length

                    start = 0
                    size = file_length
                    if size > 0x80:
                        start = (crc >> 1) % (file_length - 0x80)
                        size = 2 * file_original_length % 0x60 + 0x20

                    key = [(x + b) & 0xFF for x in range(0, 0x100)]
                    data = bytearray(data)
                    for j in range(size):
                        data[start + j] = data[start + j] ^ key[j % len(key)]

                if zflag == 1:
                    data = zlib.decompress(data)

                ext = get_ext(data)
                file_name = '{:08}.{}'.format(i, ext)

                print('{}/{}'.format(i + 1, files))
                file_path = os.path.join(folder_path, file_name)

                with open(file_path, 'wb') as dat:
                    dat.write(data)

                # === 性能优化：直接写入，而不是每次都重新打开文件 ===
                manifest.write(f"{file_sign},{file_name}\n")

                if ext in ['ktx', 'pvr']:
                    os.system('bin\\PVRTexToolCLI.exe -i {} -d -f r8g8b8a8'.format(file_path))

        # 循环结束后，manifest.txt 会被 with 语句自动关闭

        os.system('del {}\\*.ktx'.format(folder_path))
        os.system('del {}\\*.pvr'.format(folder_path))
        if statusBar != None:
            statusBar.showMessage('Unpack completed!')


def get_parser():
    parser = argparse.ArgumentParser(description='EXPK Extractor')
    parser.add_argument('path', type=str)
    opt = parser.parse_args()
    return opt


def main():
    opt = get_parser()
    unpack(opt.path)


if __name__ == '__main__':
    main()