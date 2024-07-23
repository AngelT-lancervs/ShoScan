import json
import shodan
import csv
import argparse
import time
import os

# Fixed output file names
OUTPUT_FILE = "results.csv"
SHORT_OUTPUT_FILE = "shortResults"

def write_results(results, output_file, short_output_file):
    """
    Write the results to CSV files.

    :param results: Shodan scan results
    :param output_file: Output file name to write to
    :param short_output_file: Prefix to the filename of the short version
    """
    short = results['short']
    full = results['full']

    # Write short version
    with open(output_file + "." + short_output_file, mode='w') as out_file:
        out_writer = csv.writer(out_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        for ip in short:
            try:
                for i in range(len(short[ip]['port'])):
                    out_writer.writerow([ip, short[ip]['port'][i], short[ip]['protocol'][i]])
            except KeyError:
                continue

    # Write full version
    with open(output_file, mode='w') as out_file:
        out_writer = csv.writer(out_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)
        written_rows = set()  # To track unique rows
        for ip in full:
            try:
                for item in full[ip]['all']:
                    for i in item:
                        row = (ip, i, item[i])
                        if row not in written_rows:
                            out_writer.writerow(row)
                            written_rows.add(row)
            except KeyError:
                continue
    return


def parse_shodan_search(ip_list):
    """
    Parse the Shodan search results.

    :param ip_list: List of IPs received from the user
    :return: Short (ip, port, protocol) and long results (everything)
    """
    results = {}
    short_results = {}

    for ip in ip_list:
        print("For IP: " + str(ip))
        results[ip] = {}
        short_results[ip] = {}
        port = []
        protocol = []
        rest = []

        try:
            for i in ip_list[ip]['data']:
                tmp_pro = ""
                tmp_port = ""
                for j in i:
                    if str(j) == "_shodan":
                        tmp_pro = "(" + str(i[j]['module']) + ")"
                        protocol.append(str(i[j]['module']))
                    if str(j) == "port":
                        tmp_port = "- " + str(i[j]) + " "
                        port.append(str(i[j]))
                    rest.append({str(j): str(i[j])})
                print(tmp_port + tmp_pro)

            short_results[ip] = {'port': port, 'protocol': protocol}
            results[ip] = {'all': rest}

        except TypeError:
            print("- No port found")
            print("--------- NEXT IP ---------")
            continue
        print("--------- NEXT IP ---------")

    return {'short': short_results, 'full': results}


def read_queries(file):
    """
    Read a .txt file containing queries separated by newlines.

    :param file: Name of the .txt file
    :return: List of queries
    """
    with open(file, 'r') as f:
        queries = f.read().splitlines()
    return queries

def search_shodan_query(api, queries):
    """
    Search Shodan with a query.

    :param api: Shodan API instance
    :param queries: List of query strings
    :return: Search results
    """
    results = []
    for query in queries:
        try:
            results_search = api.search(query)
            results.append({query: results_search['matches']})
        except shodan.APIError as e:
            print('Error: {}'.format(e))
            results.append({query: []})

    return results

def write_results_to_csv(results):
    """
    Write Shodan search results to a CSV file.

    :param results: List of dictionaries with search results for each query
    """
    with open(OUTPUT_FILE, mode='w', newline='') as file:
        csv_writer = csv.writer(file)
        # Write the header row
        csv_writer.writerow(['Query', 'Data'])

        # Write the results for each query
        for result in results:
            for query, matches in result.items():
                for match in matches:
                    match_data = [query] + [str(value) for value in match.values()]
                    csv_writer.writerow(match_data)

if __name__ == '__main__':
    SHODAN_API_KEY = os.getenv('SHODAN_API_KEY')
    api = shodan.Shodan(SHODAN_API_KEY)

    if SHODAN_API_KEY == "YOURKEY":
        print("Please edit the script and replace 'SHODAN_API_KEY' with your real key value")
        quit()

    # Argument parser
    parser = argparse.ArgumentParser(description='Port scanning through Shodan.io')
    parser.add_argument('--queryfile', '-q', help='File containing Shodan queries', required=True)
    parser.add_argument('--filename', '-f', help='File containing IPs (optional if queryfile is provided)')
    args = parser.parse_args()

    if args.filename:
        # Read IPs from file
        with open(args.filename, 'r') as f:
            ips = [line.strip() for line in f]

        # Search Shodan for each IP
        ip_info = {}
        for ip in ips:
            time.sleep(1)  # Forced Shodan threshold
            try:
                hostinfo = api.host(ip)
                ip_info[ip] = hostinfo
            except shodan.APIError as e:
                ip_info[ip] = '{}'.format(e)

        # Format the data
        d = json.dumps(ip_info)
        ip_list = json.loads(d)

        # Parse the data
        res = parse_shodan_search(ip_list)
        write_results(res, OUTPUT_FILE, SHORT_OUTPUT_FILE)
    
    else:
        # Read queries from file
        queries = read_queries(args.queryfile)

        # Perform search and write results
        results = search_shodan_query(api, queries)
        write_results_to_csv(results)

    print("Results have been written to the output files.")