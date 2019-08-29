import base64
import sys
from datetime import datetime, timezone
from traceback import print_exc

from mitmproxy import ctx
from mitmproxy.net.http import cookies
from mitmproxy.utils import strutils
from pymongo import MongoClient

# A list of server seen till now is maintained so we can avoid
# using 'connect' time for entries that use an existing connection.
SERVERS_SEEN = set()

MONGODB_DB = "mitmproxy"
MONGODB_COLLECTION_REQUEST = "request"
MONGODB_COLLECTION_RESPONSE = "response"
MONGODB_COLLECTION_WEBSOCKET = "websocket"
MONGODB_COLLECTION_TCP = "tcpmessage"


class HarMongoDump(object):

    def __init__(self):  # mongodb的一些配置参数
        self._SERVER = "localhost"
        self._PORT = 27017
        self._TIMEOUT = 5000
        self._MAX_POOL_SIZE = 200
        self.DB_CLIENT = None

    def configure(self, updated):  # 启动mongodb实例
        self.DB_CLIENT = MongoClient(self._SERVER, self._PORT, connect=False, serverSelectionTimeoutMS=self._TIMEOUT,
                                     maxPoolSize=self._MAX_POOL_SIZE)
        try:
            result = self.DB_CLIENT.admin.command("ismaster")
            ctx.log.info("mongo_dump configure MongoDB client initialized")
        except Exception:
            ctx.log.error(
                "mongo_dump configure DB connection problem. (server=[{0}], port=[{1}], timeout=[{2}], max_pool_size=[{3}])".format(
                    self._SERVER, self._PORT, self._TIMEOUT, self._MAX_POOL_SIZE))
            self.DB_CLIENT = None

    def request(self, flow):  # request请求
        if self.DB_CLIENT is None:
            ctx.log.error("mongo_dump request DB client None!")
            return

        try:
            entry = self.get_request_har_entry(flow)
            db = self.DB_CLIENT.get_database(MONGODB_DB)
            collection = db[MONGODB_COLLECTION_REQUEST]
            try:
                insertResult = collection.insert_one(entry)
                ctx.log.debug("mongo_dump request request_id={}".format(insertResult.inserted_id))
            except Exception as e1:
                ctx.log.error("mongo_dump request DB insert error!")
                print_exc(file=sys.stderr)
                ctx.log.error(entry)
        except Exception as e2:
            ctx.log.error("mongo_dump request Exception.")
            print_exc(file=sys.stderr)
            ctx.log.error(entry)

    def response(self, flow):  # response相应
        if self.DB_CLIENT is None:
            ctx.log.error("mongo_dump response DB client None!")
            return

        try:
            entry = self.get_response_har_entry(flow)
            db = self.DB_CLIENT.get_database(MONGODB_DB)
            collection = db[MONGODB_COLLECTION_RESPONSE]
            try:
                insertResult = collection.insert_one(entry)
                ctx.log.debug("mongo_dump response response_id={}".format(insertResult.inserted_id))
            except Exception as e1:
                ctx.log.error("mongo_dump response DB insert error!")
                print_exc(file=sys.stderr)
                ctx.log.error(entry)
        except Exception as e2:
            ctx.log.error("mongo_dump response Exception.")
            print_exc(file=sys.stderr)
            ctx.log.error(entry)

    def done(self):  # 插件结束后关闭mongodb
        if self.DB_CLIENT is not None:
            self.DB_CLIENT.close()
            ctx.log.info("mongo_dump done MongoDB client closed.")

    def get_request_har_entry(self, flow):  # request entry
        entry = {
            "startedDateTime": datetime.fromtimestamp(flow.request.timestamp_start, timezone.utc),
            "method": flow.request.method,
            "url": flow.request.url,
            "pretty_url": flow.request.pretty_url,  # my added
            "pretty_host": flow.request.pretty_host,  # my added
            "path": flow.request.path,  # my added
            "cookies": self._format_request_cookies(flow.request.cookies.fields),
            "headers": self._name_value(flow.request.headers),
            "queryString": self._name_value(flow.request.query or {})
        }

        if flow.request.method in ["POST", "PUT", "PATCH"]:
            params = [
                {"name": a, "value": b}
                for a, b in flow.request.urlencoded_form.items(multi=True)
            ]
            entry["postData"] = {
                "mimeType": flow.request.headers.get("Content-Type", ""),
                "text": flow.request.get_text(strict=False),
                "params": params
            }
            entry["text"]=flow.request.get_text(strict=False)

        if flow.client_conn.clientcert:
            entry["clientCert"] = {
                "issuer": flow.client_conn.clientcert.issuer,
                "notbefore": flow.client_conn.clientcert.notbefore,
                "notafter": flow.client_conn.clientcert.notafter,
                "subject": flow.client_conn.clientcert.subject,
                "serial": flow.client_conn.clientcert.serial,
                "cn": flow.client_conn.clientcert.cn
            }

        entry["clientIPAddress"] = flow.client_conn.address[0]

        if flow.server_conn.connected():
            entry["serverIPAddress"] = str(flow.server_conn.ip_address[0])
            entry["serverPortAddress"] = str(flow.server_conn.ip_address[1])

        return entry

    def get_response_har_entry(self, flow):  # response entry
        entry = {
            "startedDateTime": datetime.fromtimestamp(flow.request.timestamp_start, timezone.utc),
            "status": flow.response.status_code,
            "statusText": flow.response.reason,
            "cookies": self._format_response_cookies(flow.response.cookies.fields),
            "headers": self._name_value(flow.response.headers),
            "content": {},
            "redirectURL": flow.response.headers.get('Location', '')
            #            "cache": {},
        }


        entry["content"]["mimeType"] = flow.response.headers.get('Content-Type', '')

        if strutils.is_mostly_bin(flow.response.content):
            entry["content"]["text"] = base64.b64encode(flow.response.content).decode()  # Store binary data as base64
            entry["text"] = base64.b64encode(flow.response.content).decode()  # Store binary data as base64
            entry["content"]["encoding"] = "base64"
        else:
            entry["content"]["text"] = flow.response.get_text(strict=False)
            entry["text"] = flow.response.get_text(strict=False)


        if flow.server_conn.connected():
            entry["serverIPAddress"] = str(flow.server_conn.ip_address[0])
            entry["serverPortAddress"] = str(flow.server_conn.ip_address[1])
        return entry

    def _format_cookies(self, cookie_list):
        rv = []

        for name, value, attrs in cookie_list:
            cookie_har = {
                "name": name,
                "value": value,
            }

            # HAR only needs some attributes
            for key in ["path", "domain", "comment"]:
                if key in attrs:
                    cookie_har[key] = attrs[key]

            # These keys need to be boolean!
            for key in ["httpOnly", "secure"]:
                cookie_har[key] = bool(key in attrs)

            # Expiration time needs to be formatted
            expire_ts = cookies.get_expiration_ts(attrs)
            if expire_ts is not None:
                cookie_har["expires"] = datetime.fromtimestamp(expire_ts, timezone.utc)

            rv.append(cookie_har)

        return rv

    def _format_request_cookies(self, fields):
        return self._format_cookies(cookies.group_cookies(fields))

    def _format_response_cookies(self, fields):
        return self._format_cookies((c[0], c[1][0], c[1][1]) for c in fields)

    def _name_value(self, obj):
        """
            Convert (key, value) pairs to HAR format.
        """
        return [{"name": k, "value": v} for k, v in obj.items()]

    def websocket_message(self, flow):

        if self.DB_CLIENT is None:
            ctx.log.error("mongo_dump request DB client None!")
            return

        try:

            db = self.DB_CLIENT.get_database(MONGODB_DB)
            collection = db[MONGODB_COLLECTION_WEBSOCKET]
            websocketentry = {
                "startedDateTime": datetime.now(),
                "method": 'websocket',
                "serverIPAddress": str(flow.server_conn.ip_address[0]),
                "serverPortAddress": str(flow.server_conn.ip_address[1]),
                "context": str(flow.messages)
            }
            try:
                insertResult = collection.insert_one(websocketentry)
                ctx.log.debug("mongo_dump request request_id={}".format(insertResult.inserted_id))
            except Exception as e1:
                ctx.log.error("mongo_dump request DB insert error!")
                print_exc(file=sys.stderr)
                ctx.log.error(websocketentry)
        except Exception as e2:
            ctx.log.error("mongo_dump request Exception.")
            print_exc(file=sys.stderr)
            ctx.log.error(websocketentry)

    def tcp_message(self, flow):
        if self.DB_CLIENT is None:
            ctx.log.error("mongo_dump request DB client None!")
            return

        try:

            db = self.DB_CLIENT.get_database(MONGODB_DB)
            collection = db[MONGODB_COLLECTION_TCP]
            tcpentry = {
                "startedDateTime": datetime.now(),
                "method": 'tcp_message',
                "serverIPAddress": str(flow.server_conn.ip_address[0]),
                "serverPortAddress": str(flow.server_conn.ip_address[1]),
                "context": str(flow.messages)
            }
            try:
                insertResult = collection.insert_one(tcpentry)
                ctx.log.debug("mongo_dump request request_id={}".format(insertResult.inserted_id))
            except Exception as e1:
                ctx.log.error("mongo_dump request DB insert error!")
                print_exc(file=sys.stderr)
                ctx.log.error(tcpentry)
        except Exception as e2:
            ctx.log.error("mongo_dump request Exception.")
            print_exc(file=sys.stderr)
            ctx.log.error(tcpentry)


addons = [HarMongoDump()]
