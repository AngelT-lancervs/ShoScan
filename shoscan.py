import json
import shodan
import csv
import argparse
import time


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

    # For all IPs in the result
    for ip in ip_list:
        print("For IP: " + str(ip))
        results[ip] = {}
        short_results[ip] = {}
        port = []
        protocol = []
        rest = []

        try:
            # For all data per IP
            for i in ip_list[ip]['data']:
                tmp_pro = ""
                tmp_port = ""
                for j in i:
                    # Get the protocol
                    if str(j) == "_shodan":
                        tmp_pro = "(" + str(i[j]['module']) + ")"
                        protocol.append(str(i[j]['module']))
                    if str(j) == "port":
                        tmp_port = "- " + str(i[j]) + " "
                        port.append(str(i[j]))
                    rest.append({str(j): str(i[j])})
                print(tmp_port + tmp_pro)

            # Store results for short version (ip, port, protocol) or full listing of data in Shodan
            short_results[ip] = {'port': port, 'protocol': protocol}
            results[ip] = {'all': rest}

        except TypeError:
            print("- No port found")
            print("--------- NEXT IP ---------")
            continue
        print("--------- NEXT IP ---------")

    return {'short': short_results, 'full': results}


if __name__ == '__main__':
    SHODAN_API_KEY = "7lfMFJPGhPkkXbLv54eXO7Z2VHJSaJIG"
    api = shodan.Shodan(SHODAN_API_KEY)
    output_file = "results.csv"
    short_output_file = "shortResults"

    if SHODAN_API_KEY == "YOURKEY":
        print("Please edit the script and replace 'SHODAN_API_KEY' with your real key value")
        quit()

    # Argument parser
    parser = argparse.ArgumentParser(description='Port scanning through Shodan.io')
    parser.add_argument('--filename', '-f', default='iplist.txt', required=True)
    parser.add_argument('--fileout', '-o', default=output_file)
    args = parser.parse_args()

    # Read IPs from file
    with open(args.filename, 'r') as f:
        ips = [line.strip() for line in f]

    # Output info
    art = """
   ,-,--.  ,--.-,,-,--,   _,.---._      ,-,--.    _,.----.    ,---.      .-._         
 ,-.'-  _\/==/  /|=|  | ,-.' , -  `.  ,-.'-  _\ .' .' -   \ .--.'  \    /==/ \  .-._  
/==/_ ,_.'|==|_ ||=|, |/==/_,  ,  - \/==/_ ,_.'/==/  ,  ,-' \==\-/\ \   |==|, \/ /, / 
\==\  \   |==| ,|/=| _|==|   .=.     \==\  \   |==|-   |  . /==/-|_\ |  |==|-  \|  |  
 \==\ -\  |==|- `-' _ |==|_ : ;=:  - |\==\ -\  |==|_   `-' \\==\,   - \ |==| ,  | -|  
 _\==\ ,\ |==|  _     |==| , '='     |_\==\ ,\ |==|   _  , |/==/ -   ,| |==| -   _ |  
/==/\/ _ ||==|   .-. ,\\==\ -    ,_ //==/\/ _ |\==\.       /==/-  /\ - \|==|  /\ , |  
\==\ - , //==/, //=/  | '.='. -   .' \==\ - , / `-.`.___.-'\==\ _.\=\.-'/==/, | |- |  
 `--`---' `--`-' `-`--`   `--`--''    `--`---'              `--`        `--`./  `--` 
                                                              by PathetiQ - 2019/03 
    """
    print(art)
    print("------------------------------------------")
    print("Using input file: " + args.filename)
    print("Output file - all Shodan's details: " + args.fileout)
    print("Output file - short version (ip,port,protocol): " + args.fileout + "." + short_output_file)
    print("------------------------------------------\n")
    print("Launching search...")
    print("Results will be displayed after search is completed...")

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

    # Write results to CSV
    write_results(res, args.fileout, short_output_file)

    print("Results have been written to the output files.")
