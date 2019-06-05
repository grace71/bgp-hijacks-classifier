import os
import csv
import time
import pickle
import logging
from contextlib import closing
from multiprocessing import Pool
from histobgpstream import HistoBGPStream
from hegemony import GetHegemony

with open("asn2pfx.pickle", "r") as f:
    AS2PFX = pickle.load(f)

class Collect:
    def __init__(self, event, directory):
        self.event = event
        self.directory = directory

    def collect_bgp_stream(self):
        # Class HistoBGPstream deals with the following
        # We will get previous + after attack paths from BGPStream
        time_taken = time.time()
        event = self.event
        histo_handler = HistoBGPStream()
        # Get all paths per peer per collector
        # since we consider one event as a prefix event,
        # there is only one hijacked prefix
        # (https://github.com/CAIDA/bgpstream/blob/master/FILTERING)
        # Set the filter
        filter_string = 'prefix less ' + event['hijack_prefix']
        histo_handler.set_filter(filter_string)
        if ('end_time' in event) and (event['end_time'] != ''):
            paths = histo_handler.get_paths(event['start_time'], event['end_time'])
        else:
            paths = histo_handler.get_paths(event['start_time'])
        event['as_paths'] = paths
        self.event = event

        # # Store for record.
        # title = event['title'].lower().replace(" ", "_")
        # with open(os.path.join(self.directory, title + '.pickle'), "w") as f:
        #     pickle.dump(event, f)

        time_taken = time.time() - time_taken
        logging.info("[%s] Time taken for gathering bgp_paths is %s"
                     % (event['title'], time_taken))

        return event

    def collect_prefixes(self):
        # Get all prefixes announced by hijacker AS
        time_taken = time.time()
        event = self.event
        histo_handler = HistoBGPStream()

        ases = event['hijack_as']
        if event['innocent_as'] != '':
            ases = ases + ', ' + event['innocent_as']

        all_prefixes = histo_handler.get_all_prefixes_given_as\
            (ases, event['start_time'])
        event['pfxes_of_hijacker'] = all_prefixes
        self.event = event

        # # Store for record.
        # title = event['title'].lower().replace(" ", "_")
        # with open(os.path.join(self.directory, title + '.pickle'), "w") as f:
        #     pickle.dump(event, f)
        time_taken = time.time() - time_taken
        logging.info("[%s] Time taken for gathering bgp_paths is %s"
                     % (event['title'], time_taken))

        return event

    def collect_hege_paths(self):
        # Class GetHegemony returns (local/global) hegemony path
        #  + Hegemony score of origin and hijacker AS
        time_taken = time.time()
        event = self.event
        logging.info("[%s] Start collecting hege paths" % event['title'])

        enable_local_cache = False
        hege_handler = GetHegemony(event['title'], enable_local_cache)
        global_paths = dict()
        local_paths = dict()

        unique_ases_global = dict()
        unique_paths_global = dict()
        u_paths_local = dict()
        for col, P in event['as_paths'].iteritems():
            for peer, A in P.iteritems():
                for prefix, all_paths in A.iteritems():
                    for timestamp, r_type, path in all_paths:
                        if r_type == 'withdrawal':
                            continue
                        # global hegemony
                        if prefix not in unique_ases_global:
                            unique_ases_global[prefix] = set()
                        for _p in path.split(' '):
                            if '{' in _p:
                                _p = _p[1:-1]
                            unique_ases_global[prefix].add(_p)
                        if prefix not in unique_paths_global:
                            unique_paths_global[prefix] = set()
                        unique_paths_global[prefix].add(path)
                        # local hegemony
                        if prefix not in u_paths_local:
                            u_paths_local[prefix] = dict()
                        origin_as = path.split(' ')[-1]
                        if origin_as not in u_paths_local[prefix]:
                            u_paths_local[prefix][origin_as] = set()
                        u_paths_local[prefix][origin_as].add(path)

        for pfx in unique_ases_global.keys():
            hege_paths = hege_handler.get_batch_global_hege_path(unique_ases_global[pfx],
                                                    unique_paths_global[pfx], pfx,
                                                    event['start_time'])
            global_paths[pfx] = hege_paths

        for pfx in u_paths_local.keys():
            for origin_as, paths in u_paths_local[pfx].iteritems():
                hege_paths = hege_handler.get_batch_local_hege_path(paths,
                                                    pfx, event['start_time'],
                                                    origin_as)
                local_paths[pfx] = dict()
                local_paths[pfx][origin_as] = hege_paths

        event['global_paths'] = global_paths
        event['local_paths'] = local_paths
        self.event = event

        # Store for record.
        # title = event['title'].lower().replace(" ", "_")
        # with open(os.path.join(self.directory, title + '.pickle'), "w") as f:
        #     pickle.dump(event, f)

        time_taken = time.time() - time_taken
        logging.info("[%s] Time taken for gathering bgp_paths is %s"
                     % (event['title'], time_taken))


def parse_real_examples_from_csv(fpath):
    """ Parse information from csv
    :param fpath: full path for a file
    :return:
    """
    real_ex = []
    logging.info("Reading real examples from a file: %s" % fpath)
    with open(fpath, 'r') as f:
        csv_reader = csv.DictReader(f)
        for row in csv_reader:
            if 'explanation' in row:
                row.pop('explanation')
            if 'comments' in row:
                row.pop('comments')
            if 'link' in row:
                row.pop('link')
            real_ex.append(row)
    return real_ex


def get_events(directory):
    events = []
    for fname in os.listdir(directory):
        event = dict()
        event['title'] = fname.split('.pickle')[0]
        events.append(event)

    return events


def collector(event, directory):
    """ Collect
    :return:
    """
    logging.info("Starting.. event: %s" % event['title'])

    # if the file already exists, read it
    fname = event['title'] + '.pickle'
    print fname

    fpath = os.path.join(directory, fname)
    if os.path.exists(fpath):
        with open(fpath, "r") as f:
            event = pickle.load(f)
        # event['title'] = fname.split('.json')[0]
        if 'hijack_as' not in event:
            print event
        if 'victim_as' not in event:
            event['victim_as'] = str(event['original_asn'])
        if isinstance(event['hijack_as'], int):
            event['hijack_as'] = str(event['hijack_as'])
        if isinstance(event['victim_as'], int):
            event['victim_as'] = str(event['victim_as'])
        if isinstance(event['hijack_as'], list):
            temp = ''
            for asn in event['hijack_as']:
                temp += str(asn) + ','
            temp = temp[:-1]
            event['hijack_as'] = temp
        if isinstance(event['victim_as'], list):
            temp = ''
            for asn in event['victim_as']:
                temp += str(asn) + ','
            temp = temp[:-1]
            event['victim_as'] = temp
    collect = Collect(event, directory)
    # (1) Collect all AS paths
    if not 'as_paths' in event:
        event = collect.collect_bgp_stream()
        # Store for record.
        title = event['title'].lower().replace(" ", "_")
        with open(os.path.join(directory, title + '.pickle'), "w") as f:
            pickle.dump(event, f)

    # (2) Collect all prefix announced by a hijacker
    if not 'pfxes_of_hijacker' in event:
        event = collect.collect_prefixes()
        title = event['title'].lower().replace(" ", "_")
        with open(os.path.join(directory, title + '.pickle'), "w") as f:
            pickle.dump(event, f)

    # (3) Collect hegemony score for the event
    if not 'global_paths' in event or not 'local_paths' in event:
        event = collect.collect_hege_paths()
        title = event['title'].lower().replace(" ", "_")
        with open(os.path.join(directory, title + '.pickle'), "w") as f:
            pickle.dump(event, f)


    return event['title']

def run_collector(args):
    return collector(*args)

def main():
    logging.info("** Start collecting")

    # real events
    # events = parse_real_examples_from_csv('news_updated.csv')
    # bgpmon
    # events = get_events_of_bgpmon()
    # human typos
    # events = get_events_of_human_errors()
    # events = []
    # events.append({'title': 'carlson_1'})

    directory = 'collections'
    events = get_events(directory)

    stime = time.time()
    count = 0
    with closing(Pool(processes=10)) as pool:
        for title in pool.imap_unordered(run_collector,
                                         ((event, directory) for event in events),
                                         chunksize=3):
            count += 1
            logging.info("Finished collecting event .. %s, (%s/%s)" % (title, count, len(events)))
        pool.terminate()

    minutes = (time.time() - stime) / 60
    logging.info("(time taken: %s minutes)" % (minutes))
    print "(time taken: %s minutes)" % (minutes)

if __name__ == "__main__":
    log_filename = '/nfs/london/data1/shicho/log/log_' \
                   + os.path.basename(__file__).split('.')[0] + '.log'
    logging.basicConfig(format="%(levelname)s %(asctime)s: %(message)s",
                        filename=log_filename,
                        level=logging.INFO)
    main()