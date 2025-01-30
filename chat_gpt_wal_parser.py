'''

This proof-of-concept code was written to automatically extract ChatGPT conversations metadata and contents from LevelDB WAL log binary.

The script is still work-in-progress, and will require some additional edits.

'''

#!/usr/bin/python3
import re
import json
import struct
import subprocess
from datetime import datetime, UTC

def decode_message(text):
    # Existing decode_message function remains the same
    text = text.replace('\\x00', '')
    text = text.replace('\\xa4\\x01', '').replace('\\xfd\\x01', '')
    text = text.replace('\\xc9\\x07', '').replace('\\xae\\x01', '')
    text = text.replace('\\xea\\x01', '').replace('\\xc4\\x01', '')
    text = re.sub(r'\\xd8[\x00-\xff]\\xde[\x00-\xff]', ' ', text)
    text = re.sub(r'^[%\\.\\(n]', '', text)
    text = re.sub(r'^\\x[0-9a-fA-F]{2}', '', text)
    text = re.sub(r'^[Gg][Aa]\s+', '', text)
    text = re.sub(r'^x[0-9a-fA-F]{2}', '', text)
    text = re.sub(r'\\x[0-9A-Fa-f]{2}(?![0-9A-Fa-f])', '', text)
    text = re.sub(r'^[e]', '', text)
    text = text.strip()
    text = re.sub(r'^\(', '', text)
    return text

def extract_messages(text):
    # Existing extract_messages function remains the same
    messages = []
    message_positions = []
    processed_messages = set()
    
    def normalize_message(msg_tuple):
        msg_text = msg_tuple[1] if isinstance(msg_tuple, tuple) else msg_tuple
        return re.sub(r'[\s\.,!?]', '', msg_text.lower())

    utf8_patterns = [
        r'\\x04text[a-z0-9]{0,1}\\x[a-z0-9]{2}\\x[0-9]{2}([^{]+)',
        r'\\x04text\\x00\\x[a-z0-9]{2}\\x[0-9]{2}([^{]+)',
        r'\\x04textcN(.)(((?:\\x00.)*[^{]+))',
        r'request-WEB:[0-9a-fA-F\-]+-\d+"\\x04textc\\x[a-z0-9]{2}\\x[0-9]{2}([^{]+)',
        r'request-WEB:[0-9a-fA-F\-]+-\d+"\\x04text"([^{]+)'
    ]
    
    assistant_patterns = [
        r'\$([0-9a-fA-F\-]{36})"\\x04text"([^{]+)\{',
        r'2request-WEB:[0-9a-fA-F\-]+-(\d+)"\\x04text"([^{]+)\{',
        r'request-WEB:[0-9a-fA-F\-]+-\d+"\\x04text\\x00c\\xea\\x01([^{]+)\{',
        r'\\x04textc\\xea\\x01([^{]+)\{'
    ]
    
    # Process patterns (rest of the function remains the same)
    for pattern in utf8_patterns:
        for match in re.finditer(pattern, text):
            if pattern == utf8_patterns[2]:
                msg = decode_message(match.group(1) + match.group(2))
            else:
                msg = decode_message(match.group(1))
                
            if msg and len(msg) > 1:
                normalized = normalize_message(msg)
                if normalized not in {normalize_message(m[1]) for m in message_positions}:
                    pos = match.start(1)
                    message_positions.append((pos, ('assistant', msg, None)))
    
    initial_patterns = [
        r'root-nextPrompt"\\x04text"([^{]+)'
        #r'\\x08messagesa.*?root-nextPrompt"\\x04text"([^{]+)',
        #r'root"\\x04text"\\x00{\\x02.*?root-nextPrompt"\\x04text"([^{]+)'
        #r'"\\x04text"([^{]+)(?={\\x02)'  # New pattern to catch additional message format
    ]
    
    for pattern in initial_patterns:
        if initial_match := re.search(pattern, text):
            msg = decode_message(initial_match.group(1))
            if msg:
                pos = initial_match.start(1)
                message_positions.append((pos, ('user', msg, None)))
                break
    
    #for match in re.finditer(r'nextPrompt"\\x04text"([^{]+)(?={)', text):
    for match in re.finditer(r'(?<!root-)nextPrompt"\\x04text"([^{]+)(?={)', text):
        msg = decode_message(match.group(1))
        if msg:
            pos = match.start(1)
            message_positions.append((pos, ('user', msg, None)))
    
    for pattern in assistant_patterns:
        for match in re.finditer(pattern, text):
            if len(match.groups()) == 2:
                msg_id = match.group(1) if len(match.group(1)) > 10 else f"request-{match.group(1)}"
                msg = decode_message(match.group(2))
            else:
                msg = decode_message(match.group(1))
                msg_id = None
            
            if msg and len(msg) > 1:
                normalized = normalize_message(msg)
                if normalized not in {normalize_message(m[1]) for m in message_positions}:
                    pos = match.start(0)
                    message_positions.append((pos, ('assistant', msg, msg_id)))
    
    sorted_messages = []
    seen = set()
    for pos, msg_tuple in sorted(message_positions, key=lambda x: x[0]):
        normalized = normalize_message(msg_tuple[1])
        if normalized not in seen:
            sorted_messages.append(msg_tuple)
            seen.add(normalized)
    
    return sorted_messages

def clean_title(title):
    title = re.sub(r'^x[0-9a-f]+', '', title)
    title = title.strip('"')
    return title if title else "Untitled"

def decode_leveldb_timestamp(hex_str):
    bytes_list = []
    i = 0
    count = 0
    while count < 8:
        if i >= len(hex_str):
            break
        if hex_str[i:i+2] == '\\x':
            bytes_list.append(hex_str[i+2:i+4])
            i += 4
        else:
            bytes_list.append(hex(ord(hex_str[i]))[2:].zfill(2))
            i += 1
        count += 1
    
    clean_hex = ''.join(bytes_list)
    
    try:
        timestamp_bytes = bytes.fromhex(clean_hex)
        #print(f"Timestamp bytes: {timestamp_bytes.hex()}")
        timestamp = struct.unpack('<d', timestamp_bytes)[0]
        # Replace utcfromtimestamp with fromtimestamp + UTC
        dt = datetime.fromtimestamp(timestamp, UTC)
        return dt
    except Exception as e:
        return None

def parse_record(text):
    record = {'id': None, 'title': None, 'user_id': None, 'sequence': None, 'messages': [], 'timestamp': None}

    #print("\n=== Starting parse_record ===")
    #print(f"Text snippet (first 1000 chars): {text[:1000]}")
    
    #pattern = r'updateTimeN((?:\\x[0-9a-f]{2}|[A-Za-z\[\]=]){8})'
    pattern = r'updateTimeN((?:\\x[0-9a-f]{2}|[\x20-\x7E]){8})'
    match = re.search(pattern, text)
    if match:
        #print(f"Found timestamp match: {match.group(0)}")
        timestamp_bytes = match.group(1)  # Get just the captured bytes
        #print(f"Timestamp bytes: {timestamp_bytes}")
        record['timestamp'] = decode_leveldb_timestamp(timestamp_bytes)
    '''else:
        print("No timestamp match found")'''
    
    if id_match := re.search(r'[0-9a-f]{8}[-][0-9a-f]{4}[-][0-9a-f]{4}[-][0-9a-f]{4}[-][0-9a-f]{12}', text):
        record['id'] = id_match.group(0)
        record['messages'] = extract_messages(text)
    
    if seq_match := re.match(r'\s*(\d+);\s*sequence\s*(\d+)', text):
        record['sequence'] = int(seq_match.group(2))
    
    user_match = re.search(r'\\x0aauthUserId"\\x1d(user-[^"]+)', text)
    if user_match:
        record['user_id'] = user_match.group(1)
    
    if title_match := re.search(r'(?<=\\x05title"\\)(.*?)(?=\\x0aisArchivedF")', text):
        record['title'] = clean_title(title_match.group(1))
    
    return record

def run_leveldb_dump(log_file):
    """Execute leveldbutil dump command and return its output"""
    try:
        # Run leveldbutil dump command and capture output
        process = subprocess.Popen(['leveldbutil', 'dump', log_file],
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE,
                                 text=True)
        
        output, error = process.communicate()
        
        if process.returncode != 0:
            print(f"Error running leveldbutil: {error}")
            return None
            
        return output
    except Exception as e:
        print(f"Failed to run leveldbutil: {e}")
        return None

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='Parse LevelDB log file for chat conversations')
    parser.add_argument('log_file', help='Path to the LevelDB log file (e.g., 000003.log)')
    parser.add_argument('--output', '-o', default='conversations.json',
                       help='Output JSON file path (default: conversations.json)')
    
    args = parser.parse_args()
    
    # Get content directly from leveldbutil
    content = run_leveldb_dump(args.log_file)
    if not content:
        print("Failed to get content from leveldbutil")
        return
    
    conversations = {}
    processed_messages = {}
    
    for record in filter(str.strip, content.split('--- offset')):
        if data := parse_record(record):
            if conv_id := data['id']:
                if conv_id not in conversations:
                    #print(f"\nCreating new conversation {conv_id}")
                    #print(f"Initial timestamp: {data['timestamp']}")
                    conversations[conv_id] = {
                        'title': None,
                        'userId': data['user_id'],
                        'messages': [],
                        'sequences': set(),
                        'timestamp': data['timestamp']
                    }
                    #print(f"Saved timestamp: {conversations[conv_id]['timestamp']}")
                    processed_messages[conv_id] = set()
                
                if data['sequence']: 
                    conversations[conv_id]['sequences'].add(data['sequence'])
                if data['title']: 
                    conversations[conv_id]['title'] = data['title']
                
                for msg_tuple in data['messages']:
                    msg_key = (msg_tuple[0], msg_tuple[1])
                    if msg_key not in {(m[0], m[1]) for m in processed_messages[conv_id]}:
                        conversations[conv_id]['messages'].append(msg_tuple)
                        processed_messages[conv_id].add(msg_tuple)
    
    print(f"\nFound {len(conversations)} conversations:\n")
    for conv_id, data in sorted(conversations.items()):
        print("="*80)
        print(f"Title: {data['title']}")
        print(f"Conversation ID: {conv_id}")
        print(f"\nSequences: {', '.join(map(str, sorted(data['sequences'])))}")
        print(f"User auth ID: {data['userId']}")
        #print(f"\nUpdating conversation {conv_id}")
        #print(f"New timestamp: {data['timestamp']}")
        #print(f"Current timestamp: {conversations[conv_id]['timestamp']}")
        if data['timestamp']:
            print(f"Conversation start: {data['timestamp']}")
        print("\nMessages:")
        for i, (role, msg, msg_id) in enumerate(data['messages'], 1):
            print(f"{i}. [{role}] {msg}")
        print("="*80)
    
    # Convert sets to lists for JSON serialization
    for conv in conversations.values():
        conv['sequences'] = sorted(list(conv['sequences']))
        
    # Before JSON dump, convert datetime objects to strings
    for conv in conversations.values():
        if conv['timestamp']:
            conv['timestamp'] = conv['timestamp'].isoformat()
    
    with open(args.output, 'w', encoding='utf-8') as f:
        json.dump(conversations, f, indent=2, ensure_ascii=False)

if __name__ == "__main__":
    main()