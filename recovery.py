import os

def recover_raw_files(comm, drive_letter, output_dir):
    drive = f"\\\\.\\{drive_letter.upper()}:"
    block_size = 512
    offset = 0
    rcvd = 0

    signatures = [
        {"ext": "jpg", "header": b'\xff\xd8\xff\xe0\x00\x10\x4a\x46', "footer": b'\xff\xd9'},
        {"ext": "png", "header": b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a', "footer": b'\x49\x45\x4e\x44\xae\x42\x60\x82'},
        {"ext": "pdf", "header": b'%PDF', "footer": b'%%EOF'},
        {"ext": "docx", "header": b'\x50\x4B\x03\x04', "footer": b'\x50\x4B\x05\x06'},
        {"ext": "zip", "header": b'\x50\x4B\x03\x04', "footer": b'\x50\x4B\x05\x06'}
    ]

    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    try:
        with open(drive, "rb") as fileD:
            comm.log_signal.emit(f"[RAW] Scanning raw bytes from: {drive}")
            data = fileD.read(block_size)
            while data:
                for sig in signatures:
                    start = data.find(sig["header"])
                    if start >= 0:
                        file_path = os.path.join(output_dir, f"recovered_{rcvd}.{sig['ext']}")
                        comm.log_signal.emit(f"[FOUND] {sig['ext'].upper()} at offset {hex(offset * block_size + start)} → {file_path}")
                        with open(file_path, "wb") as out:
                            out.write(data[start:])
                            while True:
                                chunk = fileD.read(block_size)
                                if not chunk:
                                    break
                                end = chunk.find(sig["footer"])
                                if end >= 0:
                                    out.write(chunk[:end + len(sig["footer"])])
                                    comm.log_signal.emit(f"[RECOVERED] {file_path}")
                                    break
                                else:
                                    out.write(chunk)
                        rcvd += 1
                        break  # Move on to next block
                offset += 1
                progress = min(int((offset * block_size) / (128 * 1024 * 1024) * 100), 100)  # Simulate up to 128MB
                comm.progress_signal.emit(progress)
                data = fileD.read(block_size)
    except Exception as e:
        comm.log_signal.emit(f"[ERROR] Recovery failed: {e}")
        return

    comm.log_signal.emit(f"[DONE] {rcvd} file(s) recovered.")
    comm.recovery_status_signal.emit(f"Raw recovery complete: {rcvd} file(s)")
    comm.progress_signal.emit(100)
