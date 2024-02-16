import argparse
import pymongo
from pymongo import MongoClient
import json

def enumerate_mongodb(server, port, username=None, password=None, filename=None):
    # Connection string
    connection_string = f'mongodb://{username}:{password}@' if username and password else f'mongodb://'
    connection_string += f'{server}:{port}'

    # Connect to MongoDB
    client = MongoClient(connection_string)
    
    # Enumerating databases, collections, and documents
    enumerated_data = {}
    for db_name in client.list_database_names():
        db = client[db_name]
        enumerated_data[db_name] = {}
        for collection_name in db.list_collection_names():
            collection = db[collection_name]
            documents = list(collection.find({}))
            enumerated_data[db_name][collection_name] = documents

    # Optionally write to file
    if filename:
        with open(filename, 'w') as file:
            json.dump(enumerated_data, file, indent=4, default=str)
    else:
        print(json.dumps(enumerated_data, indent=4, default=str))

    print("Enumeration completed.")

if __name__ == "__main__":
    # Setup argument parser
    parser = argparse.ArgumentParser(description='Enumerate a MongoDB instance.')
    parser.add_argument('--server', required=True, help='Server address (e.g., localhost)')
    parser.add_argument('--port', required=True, type=int, help='Port number (e.g., 27017)')
    parser.add_argument('--username', help='Username (optional)')
    parser.add_argument('--password', help='Password (optional)')
    parser.add_argument('--filename', help='Filename to write output (optional)')

    # Parse arguments
    args = parser.parse_args()

    enumerate_mongodb(args.server, args.port, args.username, args.password, args.filename)
