#!/usr/bin/env python
import time
import logging
from itertools import groupby
from dateutil.parser import parse
from collections import defaultdict
from datetime import timedelta, datetime
from _pybgpstream import BGPStream, BGPRecord


class HistoBGPStream():
    def __init__(self):
        # Create a new bgpstream instance
        # and a reusable bgprecord instances
        self.stream = BGPStream()
        self.rec = BGPRecord()
        self.origin_ases = set()
        self.bgp_lens = defaultdict(lambda: defaultdict(lambda: None))

    def set_filter(self, string):
        """ This is optional.
        For the new version, we use stream.parse_filter_string() instead of
        stream.add_filter().
        (https://github.com/CAIDA/bgpstream/blob/master/FILTERING)
        :param string: example 'type ribs and prefix more 72.20.0.0/24 '
        :return:
        """
        logging.info("Set filter: %s" % string)
        self.stream.parse_filter_string(string)

    def convert_dt_to_timestamp(self, dt):
        """ Return utc timestamp for a given time string, or time
        """
        if isinstance(dt, str):
            dt = parse(dt)
        dt = dt.replace(tzinfo=None)
        timestamp = (dt - datetime(1970, 1, 1)).total_seconds()
        assert datetime.utcfromtimestamp(timestamp) == dt
        return int(timestamp)

    def get_paths(self, start_time, end_time=None):
        """ Return all paths for each peer for each collector
        for the given time interval.
        :param start_time: datimetime/date_string
        :param end_time: datimetime/date_string/None
        :return: paths(dict)[collector][peer-address][record-type]
                                           = (AS-path,time,prefix)
        """
        # If end_time is None, set as one hour duration.
        if isinstance(start_time, str):
            start_time = parse(start_time)
        if isinstance(end_time, str):
            end_time = parse(end_time)
        if end_time == None:
            end_time = start_time + timedelta(hours=2)

        # start collection before 8 hours
        start_time = start_time - timedelta(hours=8)

        # If start_time or end_time is not timestamp, convert them.
        if not isinstance(start_time, int):
            start_time = self.convert_dt_to_timestamp(start_time)
        if not isinstance(end_time, int):
            end_time = self.convert_dt_to_timestamp(end_time)

        paths = self.get_bgpstream(start_time, end_time)
        return paths

    def get_bgpstream(self, start_time, end_time=None):
        """ Read all rib + updates according to filters.
        You have to set filters with self.set_filter function
        before run this if you need to set some filters.
        If the time for collecting paths is too long,
        we will optimize it later. Let's record the time taken.
        :param start_time:(timestamp)
        :param end_time:(timestamp)
        :return: paths(dict)[collector][peer-address][record-type]
                                           = (AS-path,time,prefix)
        """
        logging.info("Collecting.. histo BGPStream [%s, %s]" % (start_time, end_time))
        time_taken = time.time()

        # Time intervals: mandatory
        self.stream.add_interval_filter(start_time, end_time)

        # Start the stream
        self.stream.start()

        # Get next record
        # (record is rib/updates from a single peer of a collector)
        # (each record might have many elems. an elem per a prefix)
        paths = defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: list())))
        while (self.stream.get_next_record(self.rec)):
            elem = self.rec.get_next_elem()
            while (elem):
                if ('prefix' not in elem.fields) or (elem.type == 'S'):
                    logging.debug("No prefix: %s, %s" % (elem.fields, elem.type))
                    continue
                # 0.0.0.0/0 is default, means "everything else", thus ignore!
                if elem.fields['prefix'] == '0.0.0.0/0':
                    elem = self.rec.get_next_elem()
                    continue
                # [Part 1] If you want to draw a graph, self.draw_graph(elem)
                # [Part 2] Retrieve record and elem information
                record_type = 'rib' if (self.rec.type == 'rib') else 'updates'
                # check as-path
                as_path = ''
                if 'as-path' in elem.fields:
                    # Leave it behind if it includes only origin AS
                    if len(elem.fields['as-path']) < 2:
                        elem = self.rec.get_next_elem()
                        continue
                    as_path = elem.fields['as-path']
                    # get all origin ASes
                    self.origin_ases.add(as_path.split(" ")[-1])
                # if withdrawal?
                if elem.type == 'W':
                    record_type = 'withdrawal'

                if len(paths[self.rec.collector][elem.peer_address][elem.fields['prefix']]) != 0:
                    # Traverse paths in reverse order to find the right time line.
                    length = len(paths[self.rec.collector][elem.peer_address][elem.fields['prefix']])
                    for index in reversed(range(length)):
                        p_time, p_type, p_as_path =\
                            paths[self.rec.collector][elem.peer_address][elem.fields['prefix']][index]
                        # If the current time is the last timestamp from announcements until now,
                        # just append it at the end and break. Don't need to finish the travel.
                        if self.rec.time >= p_time:
                            if p_as_path != as_path:
                                # if this is in the middle of the list, we have to check index+1 paths
                                # whether there are identical, if they are identical,
                                # delete index+1 and add this one.
                                if (index + 1 != length):
                                    f_time, f_type, f_as_path = \
                                    paths[self.rec.collector][elem.peer_address][elem.fields['prefix']][index+1]
                                    if as_path == f_as_path:
                                        logging.info("Delete the same routing info.")
                                        logging.debug("*** prefix: %s\n"
                                                      "prev: %s, %s, %s\n"
                                                      "new: %s, %s, %s\n"
                                                      "next: %s, %s, %s" % (elem.fields['prefix'],
                                                                          p_time, p_type, p_as_path,
                                                                          self.rec.time, record_type, as_path,
                                                                          f_time, f_type, f_as_path))
                                        del paths[self.rec.collector][elem.peer_address][elem.fields['prefix']][index+1]
                                paths[self.rec.collector][elem.peer_address][elem.fields['prefix']]\
                                    .insert(index+1, (self.rec.time, record_type, as_path))
                                if (index + 1 != length):
                                    if as_path == f_as_path:
                                        logging.debug("updated: %s"
                                              % paths[self.rec.collector][elem.peer_address][elem.fields['prefix']])
                            break
                        # Otherwise, just pass!
                        else:
                            logging.info("The routing info arrives later than the latest one.")
                            if (index == 0) and (record_type != 'withdrawal'):
                                logging.debug("*** prefix: %s\n"
                                              "new_path: %s, %s, %s\n"
                                              "cur_path: %s, %s, %s\n" % (elem.fields['prefix'],
                                                                         self.rec.time, record_type, as_path,
                                                                         p_time, p_type, p_as_path))
                                if as_path == p_as_path:
                                    del paths[self.rec.collector][elem.peer_address][elem.fields['prefix']][index]
                                paths[self.rec.collector][elem.peer_address][elem.fields['prefix']] \
                                    .insert(index, (self.rec.time, record_type, as_path))
                                logging.debug("updated: %s"
                                              % paths[self.rec.collector][elem.peer_address][elem.fields['prefix']])

                else:
                    paths[self.rec.collector][elem.peer_address][elem.fields['prefix']].append\
                        ((self.rec.time, record_type, as_path))

                elem = self.rec.get_next_elem()

        time_taken = time.time() - time_taken
        logging.info("Time taken for gathering histo bgpstream is %s" %time_taken)
        return paths

    def get_all_prefixes_given_as(self, ases, start_time):
        """ Collect all prefixes announced by suspected hijacker
        8 hours before the hijack events
        :param asn:
        :param start_time:
        :return:
        """
        logging.info("Start getting all prefixes for a given as: %s" % ases)
        all_prefixes = dict()
        # set a filter to get all paths ending with the given ASes
        filter_string = ''
        hijackers = [ases]
        if ',' in ases:
            hijackers = ases.split(', ')
        for hijacker in hijackers:
            if filter_string != '':
                filter_string += ' and '
            filter_string += "path %s$" % hijacker
        logging.debug("Set a filter to get all prefixes: %s" % filter_string)
        self.set_filter(filter_string)

        # Get all prefixes 8 hours before the start_time
        if isinstance(start_time, str):
            start_time = parse(start_time)
        start_collect_time = start_time - timedelta(hours=8)
        end_collect_time = start_time - timedelta(hours=1)

        # If start_time or end_time is not timestamp, convert them.
        if not isinstance(start_collect_time, int):
            start_collect_time = self.convert_dt_to_timestamp(start_collect_time)
        if not isinstance(end_collect_time, int):
            end_collect_time = self.convert_dt_to_timestamp(end_collect_time)

        # Get all historical paths between start_collect_time and end_collect_time
        paths = self.get_bgpstream(start_collect_time, end_collect_time)
        for collector in paths.keys():
            for peer in paths[collector].keys():
                for pfx in paths[collector][peer].keys():
                    for t, r_type, path in paths[collector][peer][pfx]:
                        origin_asn = path.split(' ')[-1]
                        if origin_asn not in all_prefixes:
                            all_prefixes[origin_asn] = list()
                        all_prefixes[origin_asn].append(pfx)

        for asn in all_prefixes.keys():
            all_prefixes[asn] = list(set(all_prefixes[asn]))
        return all_prefixes

    def store_real_events_to_mongodb(self):
        """ Read from excel files and store to mongodb
        """
        return

    def draw_graph(self, elem):
        """ Draw a graph from updates + ribs
        :return:
        """
        # [Part 1]
        # Get the peer ASn
        import networkx as nx
        # Create an instance of a simple undirected graph
        self.as_graph = nx.Graph()
        peer = str(elem.peer_asn)
        # Get the array of ASns in the AS path and remove repeatedly prepended ASns
        hops = [k for k, g in groupby(elem.fields['as-path'].split(" "))]
        if len(hops) > 1 and hops[0] == peer:
            # Get the origin ASn
            origin = hops[-1]
            # Add new edges to the NetworkX graph
            for i in range(0, len(hops) - 1):
                self.as_graph.add_edge(hops[i], hops[i + 1])
            # Update the AS path length between 'peer' and 'origin'
            self.bgp_lens[peer][origin] = \
                min(filter(bool, [self.bgp_lens[peer][origin], len(hops)]))
        return
