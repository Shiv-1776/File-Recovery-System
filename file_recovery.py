import os
import shutil
import re
import struct
import zipfile
import io
from PIL import Image, ImageFile
from PyPDF2 import PdfReader, PdfWriter

# Enable loading of truncated images
ImageFile.LOAD_TRUNCATED_IMAGES = True

def recover_file(comm, file_path):
    """
    Attempts to recover a corrupted file based on its extension
    Returns: Path to recovered file or None if recovery failed
    """
    ext = os.path.splitext(file_path)[1].lower()
    file_size = os.path.getsize(file_path)
    
    comm.log_signal.emit(f"[RECOVERY] Attempting to recover {file_path}")
    
    try:
        # Create a backup of the original file
        backup_path = file_path + ".backup"
        shutil.copy2(file_path, backup_path)
        comm.log_signal.emit(f"[BACKUP] Created backup at {backup_path}")
        
        if ext in ['.jpg', '.jpeg']:
            return recover_jpeg(comm, file_path)
        elif ext == '.png':
            return recover_png(comm, file_path)
        elif ext == '.pdf':
            return recover_pdf(comm, file_path)
        elif ext in ['.docx', '.xlsx', '.pptx', '.zip']:
            return recover_zip_based(comm, file_path)
        else:
            comm.log_signal.emit(f"[WARNING] No recovery method available for {ext} files")
            return None
    except Exception as e:
        comm.log_signal.emit(f"[ERROR] Recovery failed: {str(e)}")
        return None

def recover_jpeg(comm, file_path):
    """Recover corrupted JPEG files"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Check if JPEG header is intact
        if not data.startswith(b'\xff\xd8'):
            comm.log_signal.emit("[ERROR] JPEG header missing, cannot recover")
            return None
        
        # Find all Start of Scan markers
        sos_markers = [m.start() for m in re.finditer(b'\xff\xda', data)]
        if not sos_markers:
            comm.log_signal.emit("[ERROR] No SOS markers found, cannot recover")
            return None
            
        # Try to add missing End of Image marker
        if not data.endswith(b'\xff\xd9'):
            fixed_data = data + b'\xff\xd9'
            
            # Write repaired image to new file
            repaired_path = file_path + ".recovered"
            with open(repaired_path, 'wb') as f:
                f.write(fixed_data)
                
            # Verify the repaired image can be opened
            try:
                with Image.open(repaired_path) as img:
                    img.verify()
                comm.log_signal.emit("[SUCCESS] JPEG recovery successful")
                return repaired_path
            except:
                pass
        
        # Try more aggressive recovery by preserving only essential parts
        try:
            with Image.open(io.BytesIO(data)) as img:
                repaired_path = file_path + ".recovered"
                img.save(repaired_path)
                comm.log_signal.emit("[SUCCESS] JPEG recovery successful via recompression")
                return repaired_path
        except Exception as e:
            comm.log_signal.emit(f"[ERROR] JPEG recovery failed: {str(e)}")
            return None
    except Exception as e:
        comm.log_signal.emit(f"[ERROR] JPEG recovery failed: {str(e)}")
        return None

def recover_png(comm, file_path):
    """Recover corrupted PNG files"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Check if PNG signature is intact
        png_signature = b'\x89PNG\r\n\x1a\n'
        if not data.startswith(png_signature):
            comm.log_signal.emit("[ERROR] PNG signature missing, cannot recover")
            return None
        
        # Try to repair by recompressing
        try:
            with Image.open(io.BytesIO(data)) as img:
                repaired_path = file_path + ".recovered"
                img.save(repaired_path)
                comm.log_signal.emit("[SUCCESS] PNG recovery successful via recompression")
                return repaired_path
        except Exception as inner_e:
            # More advanced recovery - extract valid chunks
            try:
                # PNG consists of signature followed by chunks
                # Each chunk has: length (4 bytes), type (4 bytes), data, CRC (4 bytes)
                offset = len(png_signature)
                valid_data = bytearray(png_signature)
                
                while offset < len(data) - 12:  # Need at least 12 bytes for chunk header + CRC
                    try:
                        chunk_length = struct.unpack('>I', data[offset:offset+4])[0]
                        chunk_type = data[offset+4:offset+8]
                        
                        # Validate chunk type (must be ASCII letters)
                        if not all(32 < b < 127 for b in chunk_type):
                            offset += 1
                            continue
                            
                        # Check if we can safely read this chunk
                        if offset + chunk_length + 12 > len(data):
                            break
                            
                        # Add this chunk to our valid data
                        chunk_data = data[offset:offset+chunk_length+12]
                        valid_data.extend(chunk_data)
                        
                        offset += chunk_length + 12
                    except:
                        offset += 1
                
                # Ensure we have an IEND chunk
                if not valid_data.endswith(b'IEND\xaeB`\x82'):
                    valid_data.extend(b'\x00\x00\x00\x00IEND\xaeB`\x82')
                
                # Write repaired PNG
                repaired_path = file_path + ".recovered"
                with open(repaired_path, 'wb') as f:
                    f.write(valid_data)
                
                # Verify
                try:
                    with Image.open(repaired_path) as img:
                        img.verify()
                    comm.log_signal.emit("[SUCCESS] PNG recovery successful with chunk analysis")
                    return repaired_path
                except:
                    os.remove(repaired_path)
                    comm.log_signal.emit("[ERROR] PNG recovery failed during verification")
                    return None
            except Exception as e:
                comm.log_signal.emit(f"[ERROR] Advanced PNG recovery failed: {str(e)}")
                return None
    except Exception as e:
        comm.log_signal.emit(f"[ERROR] PNG recovery failed: {str(e)}")
        return None

def recover_pdf(comm, file_path):
    """Recover corrupted PDF files"""
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        # Check if PDF header is intact
        if not data.startswith(b'%PDF'):
            comm.log_signal.emit("[ERROR] PDF header missing, cannot recover")
            return None
        
        # Try to add EOF marker if missing
        if not b'%%EOF' in data:
            fixed_data = data + b'\n%%EOF\n'
            
            # Write repaired file
            repaired_path = file_path + ".recovered"
            with open(repaired_path, 'wb') as f:
                f.write(fixed_data)
                
            # Try to validate by opening with PyPDF2
            try:
                with open(repaired_path, 'rb') as f:
                    pdf = PdfReader(f)
                    num_pages = len(pdf.pages)
                    comm.log_signal.emit(f"[SUCCESS] PDF recovery successful, {num_pages} pages")
                    return repaired_path
            except:
                os.remove(repaired_path)
                comm.log_signal.emit("[ERROR] PDF recovery failed during validation")
        
        # Try more aggressive recovery by extracting valid pages
        try:
            repaired_path = file_path + ".recovered"
            reader = PdfReader(io.BytesIO(data), strict=False)
            writer = PdfWriter()
            
            # Try to copy each valid page
            valid_pages = 0
            for i in range(len(reader.pages)):
                try:
                    page = reader.pages[i]
                    writer.add_page(page)
                    valid_pages += 1
                except:
                    continue
            
            if valid_pages > 0:
                with open(repaired_path, 'wb') as f:
                    writer.write(f)
                comm.log_signal.emit(f"[SUCCESS] PDF recovery successful, saved {valid_pages} valid pages")
                return repaired_path
            else:
                comm.log_signal.emit("[ERROR] No valid PDF pages found")
                return None
        except Exception as e:
            comm.log_signal.emit(f"[ERROR] PDF recovery failed: {str(e)}")
            return None
    except Exception as e:
        comm.log_signal.emit(f"[ERROR] PDF recovery failed: {str(e)}")
        return None

def recover_zip_based(comm, file_path):
    """Recover ZIP-based files (.zip, .docx, .xlsx, etc.)"""
    try:
        # Try to open and test the zip file
        repaired_path = file_path + ".recovered"
        
        try:
            # Try to extract valid files from the archive
            with zipfile.ZipFile(file_path, 'r') as zip_ref:
                # Create a new zip file
                with zipfile.ZipFile(repaired_path, 'w') as new_zip:
                    # Try to copy each file
                    file_count = 0
                    for item in zip_ref.namelist():
                        try:
                            data = zip_ref.read(item)
                            new_zip.writestr(item, data)
                            file_count += 1
                        except:
                            comm.log_signal.emit(f"[WARNING] Skipping corrupted item: {item}")
                    
                    if file_count > 0:
                        comm.log_signal.emit(f"[SUCCESS] ZIP recovery successful, saved {file_count} files")
                        return repaired_path
                    else:
                        comm.log_signal.emit("[ERROR] No valid files found in ZIP")
                        os.remove(repaired_path)
                        return None
        except zipfile.BadZipFile:
            # More aggressive recovery for severely corrupted zip files
            comm.log_signal.emit("[ATTEMPT] Trying advanced ZIP recovery...")
            
            with open(file_path, 'rb') as f:
                data = f.read()
            
            # Look for local file headers
            local_headers = [m.start() for m in re.finditer(b'PK\x03\x04', data)]
            
            if not local_headers:
                comm.log_signal.emit("[ERROR] No ZIP headers found, cannot recover")
                return None
                
            # Try to salvage files from each local header
            salvaged = False
            with zipfile.ZipFile(repaired_path, 'w') as new_zip:
                for header_pos in local_headers:
                    try:
                        # Read the header information
                        header_data = data[header_pos:header_pos+30]  # Local file header is 30 bytes
                        if len(header_data) < 30:
                            continue
                            
                        # Parse header fields
                        filename_length = struct.unpack('<H', header_data[26:28])[0]
                        extra_field_length = struct.unpack('<H', header_data[28:30])[0]
                        
                        # Extract filename
                        if header_pos + 30 + filename_length > len(data):
                            continue
                            
                        filename = data[header_pos+30:header_pos+30+filename_length].decode('utf-8', errors='ignore')
                        
                        # Skip directories
                        if filename.endswith('/'):
                            continue
                            
                        # Extract compressed data - size unknown, so read until next header or EOF
                        data_start = header_pos + 30 + filename_length + extra_field_length
                        data_end = len(data)
                        
                        # Find next header if any
                        next_headers = [pos for pos in local_headers if pos > data_start]
                        if next_headers:
                            data_end = min(next_headers)
                            
                        # Limit maximum recovery size
                        max_size = 10 * 1024 * 1024  # 10MB max per file
                        if data_end - data_start > max_size:
                            data_end = data_start + max_size
                            
                        # Store file data
                        file_data = data[data_start:data_end]
                        
                        # Store as uncompressed
                        new_zip.writestr(filename, file_data)
                        salvaged = True
                        comm.log_signal.emit(f"[SALVAGED] Recovered file: {filename}")
                    except Exception as e:
                        continue
            
            if salvaged:
                comm.log_signal.emit("[SUCCESS] ZIP recovery partially successful")
                return repaired_path
            else:
                comm.log_signal.emit("[ERROR] ZIP recovery failed")
                os.remove(repaired_path)
                return None
    except Exception as e:
        comm.log_signal.emit(f"[ERROR] ZIP recovery failed: {str(e)}")
        return None