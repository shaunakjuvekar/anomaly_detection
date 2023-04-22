import re
from time import sleep
import json
from kafka import KafkaProducer

def to_dict(filename):
    cnt = 0
    with open(filename) as f:
        arr_dict = []
        for line in f:
            #if cnt>10:
            #    break
            #cnt+=1
            
            pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
            timestamp = line[0:re.search('LabSZ',line).start()-1]
            code = line[re.search('LabSZ',line).start()+6:re.search('\d]:', line).start()+2]
            message = line[re.search('\d]:', line).start()+4:-1]
            ip_found = re.search(pattern,line)
            ip_address = pattern.search(line)[0] if ip_found else 0

            label_dict = {
                "connection_closed" : "Connection closed", "failed_password" : "Failed password",
                "auth_failure" : "pam_unix", "disconnect" : "Bye Bye", "message_repeated": "message repeated" ,
                "break_in_attempt" : "POSSIBLE BREAK-IN ATTEMPT!", "no_identification": " Did not receive identification",
                "invalid_user" : "input_userauth_request"
            }
            label = "no label"
            for key,values in label_dict.items():
                if values in message:
                    label = key

            log_dict = {"timestamp": timestamp, "code":code,"message":message, "ip_address":ip_address,
            "label" : label}
            arr_dict.append(log_dict)
    
    return arr_dict

def stream_file_lines(filename, p):
    arr_dict = to_dict(filename)
    
    for obj in arr_dict:
        
        print(obj)
        p.send('ssh', key='', value=obj)
   
        # This adjusts the rate at which the data is sent. Use a slower rate for testing your code.
        sleep(1)


producer = KafkaProducer(
    bootstrap_servers=['localhost:9092'],
    api_version=(0,11,5),
    value_serializer=lambda x: json.dumps(x).encode('utf-8'),
    key_serializer=lambda x: x.encode('utf-8')
)

# Top level call to stream the data to kafka topic. Provide the path to the data. Use a smaller data file for testing.
stream_file_lines("log_file.log", producer)
