# Anomaly Detection System

CS5614 Project

1. First start the docker container by this command:-
 
docker-compose -f docker-compose-expose.yml up

2. Then start the producer file :
 
python producer.py

# File Descriptions

## data_parser.py
This file can parse the SSH file and generate CSV data in the format that the ML model will take in. We can use the 
same schema for Spark processing as well. You can find the column names in the "logs" object of the LogParser class in 
the same file. This file houses the logic for labelling anomalies.

**INPUT**: `assets/SSH.log` **OUTPUT**: `assets/log_data.csv`


NOTE: There are 3 ways to get information from the parser.
1. To parse one line at a time, `parse()` can be called for every line.
2. To get entire data as list of lists, `get()` can be used.
3. To get entire data as dataframe, `get_as_dataframe()` can be used.


    from data_parser import LogParser

    parser = LogParser()

    line_dict = parser.parse(log_line)      # Useful for returning single row of data
    parsed_data = parser.get()              # Useful for returning all data as list of lists
    dataframe = parser.get_as_dataframe()   # Useful for returning all data as dataframe


## learner.ipynb
This file reads the processed data and trains a machine learning model. It should save the model in `.pkl` format.
Some starter code has already been added to the file.

**INPUT**: `assets/log_data.csv` **OUTPUT**: `a pickle file that stores the model`


## assets directory
* **`SSH.log`**: Main log file.
* `log_file.log`: A sample of the main log file (2000 lines).
* `tmp_log.log`: A sample of the main log file (10000 lines).
* `log_data.csv`: Processed data for the training and testing of ML model. Same structure of data should be provided
to the model as input.