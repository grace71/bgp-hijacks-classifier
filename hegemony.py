# get hegemony score of local and global
# ihr.iijlab.net/ihr/api/hegemony/?originasn=0&asn=2497&af=4&timebin__gte=2017-11-20T00:00&timebin__lte=2017-11-21T23:59
import logging
import requests
from pymongo import MongoClient
from dateutil.parser import parse
from datetime import datetime, timedelta


class GetHegemony():
    def __init__(self, title, local_cache=False):
        self.base_url = "https://ihr.iijlab.net/ihr/api/hegemony/?"
        self.hegemony = {'global': dict(), 'local': dict()}
        self.hours_ago_before_the_event = 2
        self.local_cache = local_cache
        self.title = title
        self.origin_ases = set()
        if self.local_cache:
            mongoclient = MongoClient("localhost:27017")
            self.db = mongoclient.hijacks

    def check_ip_version(self, prefix):
        """ We are sure that the prefix is valid ip addresses.
        And we just want to simply check whether it is ipv4 or ipv6
        """
        if ':' in prefix:
            return '6'
        return '4'

    def check_hege_in_mongodb(self, asn, timebin, af, type):
        """ Check whether we have local cache
        :param asn:(int)
        :param timebin:(datetime)
        :param af:(int)
        :param type: either 'global' or 'local'
        :return:
        """
        return self.db.hegemony.find_one \
            ({'asn': int(asn), 'timebin': timebin, 'af': int(af), 'type': type})

    def insert_hege_to_mongodb(self, asn, timebin, af, type, rsp):
        """ Store hegemony to our local cache for debugging
        :param asn:(int)
        :param timebin:(datetime)
        :param af:(int)
        :param type:(str)
        :param rsp:
        :return:
        """
        rsp['type'] = type
        rsp['asn'] = int(asn)
        rsp['timebin'] = timebin
        rsp['af'] = int(af)
        if 'next' in rsp:
            rsp.pop('next')
        if 'previous' in rsp:
            rsp.pop('previous')
        if 'count' in rsp:
            rsp.pop('count')
        self.db.hegemony.insert(rsp)

    def query_to_get_hegemony(self, asn, dt_time, af, type):
        """ Query to the IIJ server for hegemony score.
        :param asn:
        :param dt_time:
        :param af:
        :return:
        """
        if '{' in asn:
            asn = asn[-1,1]
        # when local_cache is True, check whether we have local store
        if self.local_cache:
            rsp = self.check_hege_in_mongodb(asn, dt_time, af, type)
            if rsp: return rsp['results']
        query_time = datetime.strftime(dt_time, '%Y-%m-%dT%H:%M')
        query_url = ''
        if type == 'global':
            global_api = "originasn=0&af=%s&timebin=%s&format=json&asn=%s"
            query_url = self.base_url + global_api % (af, query_time, asn)
        elif type == 'local':
            local_api = "originasn=%s&af=%s&timebin=%s&format=json"
            query_url = self.base_url + local_api % (asn, af, query_time)
        if query_url == '':
            raise ValueError('query url is required, but missed')
        rsp = requests.get(query_url)
        rsp = rsp.json()

        if 'results' in rsp and len(rsp['results']) == 0:
            gte_time = datetime.strftime(dt_time - timedelta(minutes=10), '%Y-%m-%dT%H:%M')
            lte_time = datetime.strftime(dt_time + timedelta(minutes=10), '%Y-%m-%dT%H:%M')
            updated = '&timebin__gte=%s&timebin__lte=%s&format' % (gte_time, lte_time)
            query_url = query_url.split('&timebin')[0] + updated + query_url.split('&format')[1]
            rsp = requests.get(query_url)
            rsp = rsp.json()

        if ('results' in rsp) and (len(rsp['results']) != 0):
            # Store rsp of the new query
            if self.local_cache:
                self.insert_hege_to_mongodb(asn, dt_time, af, type, rsp)
            return rsp['results']
        else:
            if 'details' in rsp:
                logging.info("details: %s" %rsp['details'])
            logging.info("Could not find hegemony: query(%s)" % query_url)
            return None

    def get_hegemony(self, asn, dt_time, af, type):
        """ Get hegemony score for the given AS, if we don't have
        then query to the IIJ server.
        :param asn:
        :param dt_time: datetime
        :param af: str
        :param type: str 'global' or ' local'
        :return:
        """
        if (asn in self.hegemony[type]) and (af in self.hegemony[type][asn]) \
                and (dt_time in self.hegemony[type][asn][af]):
            return self.hegemony[type][asn][af][dt_time]

        results = self.query_to_get_hegemony(asn, dt_time, af, type)
        if asn not in self.hegemony[type]:
            self.hegemony[type][asn] = dict()
        if af not in self.hegemony[type][asn]:
            self.hegemony[type][asn][af] = dict()
        if dt_time not in self.hegemony[type][asn][af]:
            self.hegemony[type][asn][af][dt_time] = dict()
        if results:
            for this in results:
                self.hegemony[type][asn][af][dt_time][this['asn']] = this['hege']
            return self.hegemony[type][asn][af][dt_time]
        else:
            self.hegemony[type][asn][af][dt_time][int(asn)] = 0
            return self.hegemony[type][asn][af][dt_time]

    def get_local_hege_path(self, path, pfx, start_time, origin_as):
        """ Given as-path, return local hegemony path
        We will use the hegemony score of the AS before 3 hour
        :param path:
        :param pfx:
        :param start_time:
        :param ases:
        :return:
        """
        if isinstance(path, str):
            path = path.split(' ')
        if isinstance(start_time, int):
            start_time = datetime.fromtimestamp(start_time)
        start_time = self.ceil_dt(start_time)
        # 1 hours is default
        start_time = start_time - timedelta(hours=self.hours_ago_before_the_event)
        version = self.check_ip_version(pfx)
        ## origin ases
        hege_paths = dict()
        # For the same path, we'd like to check local hegemony of each different origin ASes.
        # (We need to explain in a better way to make others clear why we did it.)
        # for origin_as in self.origin_ases:
        rsp = self.get_hegemony(origin_as, start_time, version, 'local')
        hege_path = []
        for asn in path:
            if rsp and (int(asn) in rsp):
                hege_path.append(rsp[int(asn)])
            else:
                hege_path.append(0)
        hege_path = " ".join(str(x) for x in hege_path)
        hege_paths[origin_as] = hege_path
        return hege_paths

    def get_global_hege_path(self, path, pfx, start_time):
        """ Given as-path, return global hegemony path
        We will use the hegemony score of the AS before 1 hour
        :param path: (string) as-path
        :param pfx: to check IP version
        :param start_time:(timestamp)
        :return:
        """
        # TODO: the start_time should be the start_timge of the event, not timestamp of path.
        if isinstance(path, str):
            path = path.split(' ')
        if isinstance(start_time, int):
            start_time = datetime.fromtimestamp(start_time)
        # mandatory!
        start_time = self.ceil_dt(start_time)
        start_time = start_time - timedelta(hours=self.hours_ago_before_the_event)
        version = self.check_ip_version(pfx)

        hege_path = []
        for asn in path:
            rsp = self.get_hegemony(asn, start_time, version, 'global')
            if rsp:
                hege_path.append(rsp[int(asn)])
            else:
                hege_path.append(0)
        hege_path = " ".join(str(x) for x in hege_path)
        return hege_path

    def get_batch_global_hege_path(self, unique_ases, unique_paths, pfx, start_time, hj_as=[]):
        """
        :return:
        """
        dt_time = self.get_hege_time(start_time)
        query_time = datetime.strftime(dt_time, '%Y-%m-%dT%H:%M')
        af = self.check_ip_version(pfx)

        unique_ases = unique_ases | set(hj_as)
        logging.info("reading %s ASes from IIJ" %(len(unique_ases)))

        url = "https://ihr.iijlab.net/ihr/api/hegemony/?" \
              "originasn=0&af=%s&timebin=%s&format=json&asn=%s" \
              % (af, query_time, ','.join(unique_ases))
        rsp = requests.get(url)
        rsp = rsp.json()

        if 'results' in rsp and len(rsp['results']) == 0:
            gte_time = dt_time - timedelta(minutes=10)
            gte_time = datetime.strftime(gte_time, '%Y-%m-%dT%H:%M')
            lte_time = dt_time + timedelta(minutes=10)
            lte_time = datetime.strftime(lte_time, '%Y-%m-%dT%H:%M')
            url = 'https://ihr.iijlab.net/ihr/api/hegemony/?' \
                 'originasn=0&af=%s&timebin__gte=%s&timebin__lte=%s&format=json&asn=%s'\
                  % (af, gte_time, lte_time, ','.join(unique_ases))
            rsp = requests.get(url)
            rsp = rsp.json()

        hegemony = dict()
        if 'results' in rsp and len(rsp['results']) != 0:
            for result in rsp['results']:
                hegemony[str(result['asn'])] = result['hege']
        else:
            assert("no hegemony results")

        hege_paths = []
        for path in unique_paths:
            path = path.split(' ')
            new_path = [v for i, v in enumerate(path) if i == 0 or v != path[i - 1]]
            hege_paths.append((new_path, [hegemony[asn] if asn in hegemony else 0 for asn in new_path]))

        global_hj_as = dict()
        for asn in hj_as:
            if asn in hegemony:
                global_hj_as[asn] = hegemony[asn]

        return hege_paths, global_hj_as

    def get_batch_local_hege_path(self, paths, pfx, start_time, origin_as):
        if '{' in origin_as:
            origin_as = origin_as[1:-1]
        dt_time = self.get_hege_time(start_time)
        af = self.check_ip_version(pfx)

        rsp = self.get_hegemony(origin_as, dt_time, af, 'local')

        hege_paths = []
        for path in paths:
            path = path.split(' ')
            new_path = [v for i, v in enumerate(path) if i == 0 or v != path[i - 1]]
            hege_path = []
            for asn in new_path:
                if rsp and (int(asn) in rsp):
                    hege_path.append(rsp[int(asn)])
                else:
                    hege_path.append(0)
            hege_paths.append((new_path, hege_path))

        # want to check whether local hegemony changed over time
        gte_time = datetime.strftime(dt_time - timedelta(hours=2), '%Y-%m-%dT%H:%M')
        lte_time = datetime.strftime(dt_time + timedelta(hours=2), '%Y-%m-%dT%H:%M')
        query_url = "https://ihr.iijlab.net/ihr/api/hegemony/?" \
                    "originasn=%s&af=%s&timebin__gte=%s" \
                    "&timebin__lte=%s&format=json" % (origin_as, af, gte_time, lte_time)
        rsp = requests.get(query_url)
        rsp = rsp.json()
        local_hege = dict()
        for re in rsp['results']:
            if not re['timebin'] in local_hege:
                local_hege[re['timebin']] = dict()
            local_hege[re['timebin']][re['asn']] = re['hege']

        if len(rsp['results']) == 0:
            print 'no local hegemony: %s' %query_url

        return hege_paths, local_hege

    def get_hege_time(self, timestring):
        """ new time for querying hegemony
        :param timestring:
        :return:
        """
        if isinstance(timestring, str):
            timestring = parse(timestring)
        if isinstance(timestring, int):
            timestring = datetime.fromtimestamp(timestring)
        # mandatory!
        dt_time = self.ceil_dt(timestring)
        # 1 hour is default for now
        # we have to find a better time difference and good reason
        dt_time = dt_time - timedelta(hours=self.hours_ago_before_the_event)
        return dt_time

    def ceil_dt(self, dt, roundup=False):
        """ Currently, hegemony is calculated every 15 minute,
        You have to query with time 0, 15, 30, 45 minutes,
        otherwise, you will receive an empty response.
        This function rounds up to nearest 15 muiltiple.
        """
        if dt.minute % 15 or dt.second:
            if roundup:
                return dt + timedelta(minutes=15-dt.minute % 15,
                                  seconds=-(dt.second % 60))
            else:
                return dt - timedelta(minutes=dt.minute % 15,
                                  seconds=dt.second % 60)
        else:
            return dt

