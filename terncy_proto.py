#!/usr/bin/env python3
"""
小燕(Terncy) xlive 协议 protobuf 编解码器
==========================================
纯 Python、零依赖。字段编号来自 blutter 汇编提取（PROTO_FIELDNOS.json），
枚举数值来自快照对象池转储（见 RE_DEEPEN2.md 第二节）。

设计要点
--------
1. 只覆盖假云端真正需要读写的消息，不做全量 schema 生成器；
   字段号有变动的类集中在 `FIELDS` 表里，改一处即可。
2. 解析一律「宽容」：未知字段原样保留（`raw`），重复字段收成 list。
3. 编码重复标量默认 **unpacked**（每个值一个 tag）。proto3 解析器两种都收，
   而 unpacked 不会因为 packed 解析差异翻车。
4. 信封回显：假云端不需要理解 Message.Time 的内部结构，
   直接把请求里的原始字节抄回响应即可（`time_raw`）。

消息全景（本项目关心的部分）
---------------------------
Message { 1 MessageID, 2 CorrelationID, 3 Sender, 4 Time,
          10 Error, 11 OnOff, 12 OnOffResult, 13 GetEntity, 14 GetEntityResult,
          41 ReadAttribute, 42 ReadAttributeResult, 63 WriteAttribute,
          64 WriteAttributeResult, 88 GetCloudServer, 89 GetCloudServerResult,
          90 SetCloudServer, 91 SetCloudServerResult }
Event   { 1 MessageID, 2 Sender, 3 Time, 8 DeviceAttrReport, 9 OnOffStatusChanged,
          29 EntityUpdated, 30 EntityCreated, 31 EntityDeleted }

注意：部署服务器为 Python 3.6.8，不使用 `from __future__ import annotations`（3.7+）
"""
import struct
import uuid

# ---------------------------------------------------------------- wire 基础


def varint(n: int) -> bytes:
    if n < 0:
        n += 1 << 64
    out = bytearray()
    while True:
        b = n & 0x7F
        n >>= 7
        out.append(b | 0x80 if n else b)
        if not n:
            return bytes(out)


def read_varint(buf: bytes, i: int):
    val = 0
    shift = 0
    while True:
        b = buf[i]
        i += 1
        val |= (b & 0x7F) << shift
        if not b & 0x80:
            return val, i
        shift += 7


def _tag(field: int, wt: int) -> bytes:
    return varint((field << 3) | wt)


def enc_uint(field: int, value: int) -> bytes:
    return _tag(field, 0) + varint(int(value))


def enc_bool(field: int, value: bool) -> bytes:
    return _tag(field, 0) + varint(1 if value else 0)


def enc_bytes(field: int, value: bytes) -> bytes:
    return _tag(field, 2) + varint(len(value)) + value


def enc_str(field: int, value: str) -> bytes:
    return enc_bytes(field, value.encode("utf-8"))


def enc_msg(field: int, body: bytes) -> bytes:
    return enc_bytes(field, body)


def enc_repeated_uint(field: int, values, packed: bool = False) -> bytes:
    """重复标量/枚举。默认 unpacked（兼容性最好）。"""
    values = list(values)
    if not values:
        return b""
    if packed:
        return enc_bytes(field, b"".join(varint(v) for v in values))
    return b"".join(enc_uint(field, v) for v in values)


# ---------------------------------------------------------------- 解析


def parse(buf: bytes) -> dict:
    """把 protobuf 字节流拆成 {field_no: [value, ...]}。

    value 形态：varint -> int；length-delimited -> bytes。
    调用方按需再解一层（见 as_str/as_msg）。
    """
    out: dict[int, list] = {}
    i, n = 0, len(buf)
    while i < n:
        key, i = read_varint(buf, i)
        field, wt = key >> 3, key & 7
        if wt == 0:
            v, i = read_varint(buf, i)
        elif wt == 2:
            ln, i = read_varint(buf, i)
            v = buf[i:i + ln]
            i += ln
        elif wt == 5:
            v = buf[i:i + 4]
            i += 4
        elif wt == 1:
            v = buf[i:i + 8]
            i += 8
        else:
            raise ValueError(f"unsupported wire type {wt} at {i}")
        out.setdefault(field, []).append(v)
    return out


def one(d: dict, field: int, default=None):
    v = d.get(field)
    return v[0] if v else default


def as_str(v) -> str:
    return v.decode("utf-8", "replace") if isinstance(v, (bytes, bytearray)) else ""


def as_msg(v) -> dict:
    return parse(v) if isinstance(v, (bytes, bytearray)) else {}


def ints(d: dict, field: int) -> list:
    """读重复标量，自动兼容 packed（一个 length-delimited 里塞多个 varint）。"""
    out = []
    for v in d.get(field, []):
        if isinstance(v, int):
            out.append(v)
        else:
            i = 0
            while i < len(v):
                x, i = read_varint(v, i)
                out.append(x)
    return out


# ---------------------------------------------------------------- 枚举
# 数值来源：pp.txt 中 ProtobufEnum 实例的 off_8（值）+ off_10（名），
# 已用「值 = 对象地址在 List<Enum> 中的下标」交叉验证（见 RE_DEEPEN2 §2）。

ENTITY_TYPE = {
    0: "EntityDevice", 1: "EntityScene", 2: "EntityRoom", 3: "EntityBinding",
    4: "EntitySystem", 6: "EntityAutomation", 7: "EntityAutomationSet",
    8: "EntityLanToken", 9: "EntityUser", 10: "EntityArea",
    11: "EntityGroupedDevice", 12: "EntityLockKey", 13: "EntityMediaFile",
}

# 已实锤的 AttributeID（57/239）。未列出的按「未知」处理，不参与编码。
ATTR_ID = {
    0: "on", 1: "totalPower", 2: "activePower", 4: "occupancy", 5: "luminance",
    6: "temperature", 7: "binInputStatus", 13: "position", 15: "alertLevel",
    16: "windowMotorStatus", 23: "occupancyLeft", 24: "occupancyRight",
    26: "disableRelay", 31: "enableKeepOnOffStatus", 35: "autoEnabled",
    38: "pureInput", 40: "swPolarity", 44: "currentLevel",
    45: "disabledRelayStatus", 46: "numOfTimeoutControls", 48: "zhhRunning",
    49: "acTargetTemperature", 50: "acCurrentTemperature", 51: "acFanSpeed",
    52: "acWorkMode", 54: "mutexedIndex", 56: "buttonLedPolarity",
    59: "autoSetTypeId", 61: "colorTemperature", 73: "doorLockState",
    78: "iasZoneStatus", 79: "humidity", 85: "playerVolume",
    86: "playerControlState", 89: "autoSetEnabled", 90: "subsystemName",
    91: "playerMuteState", 92: "playerPlayingMode", 93: "entityIconId",
    94: "hue", 95: "saturation", 100: "singleClickCount",
    101: "doubleClickCount", 102: "tripleClickCount", 108: "homeKitEnabled",
    132: "usageLevel", 140: "inputSourceIndex", 142: "appInstallSourceIndex",
    162: "xylcCurrentLevel", 163: "deviceHomeKitEnabled", 188: "windowTilt",
    207: "verificationCode", 210: "presenceStatus", 217: "acAccurateSpeed",
    223: "fanSpeed", 224: "fanDirection", 228: "boundLedIndicators",
}
ATTR_BY_NAME = {v: k for k, v in ATTR_ID.items()}
# 推断值（未实锤）：按枚举声明顺序，3 位于 ActivePower(2) 与 Occupancy(4) 之间
ATTR_GUESS = {3: "brightness", 8: "battery"}

ONOFF_COMMAND = {0: "Off", 1: "On"}          # Off 已实锤；On=1 为唯一合理取值
WRITE_ATTR_TYPE = {0: "WriteInt", 1: "WriteBool", 2: "WriteString"}

# ---------------------------------------------------------------- Message 信封

MSG_ONOFF = 11
MSG_ONOFF_RESULT = 12
MSG_GET_ENTITY = 13
MSG_GET_ENTITY_RESULT = 14
MSG_CREATE_SCENE = 15
MSG_CREATE_SCENE_RESULT = 16
MSG_UPDATE_SCENE = 17
MSG_UPDATE_SCENE_RESULT = 18
MSG_DELETE_SCENE = 19
MSG_DELETE_SCENE_RESULT = 20
MSG_SET_SCENE_ONOFF = 21          # SetSceneOnOffRequest {1 UUID, 2 Command(enum)}
MSG_SET_SCENE_ONOFF_RESULT = 22   # SetSceneOnOffResponse {1 UUID, 2 OnOff, 3 Stage(enum)}
MSG_CREATE_ROOM = 33
MSG_CREATE_ROOM_RESULT = 34
MSG_DELETE_ROOM = 35
MSG_DELETE_ROOM_RESULT = 36
MSG_READ_ATTRIBUTE = 41
MSG_READ_ATTRIBUTE_RESULT = 42
MSG_GET_TIME = 51
MSG_GET_TIME_RESULT = 52          # GetTimeResponse {1 Time:str, 2 TimeZone:str}
MSG_WRITE_ATTRIBUTE = 63
MSG_WRITE_ATTRIBUTE_RESULT = 64
MSG_GET_CLOUD_SERVER = 88
MSG_GET_CLOUD_SERVER_RESULT = 89
MSG_SET_CLOUD_SERVER = 90
MSG_SET_CLOUD_SERVER_RESULT = 91
MSG_ERROR = 10

EVT_DEVICE_ATTR_REPORT = 8
EVT_ONOFF_STATUS_CHANGED = 9
# Event.presence = 27（event.pb.dart，PROTO_FIELDNOS.json 实锤）
# 这是「家庭中心在线」的唯一运行时信号：App 收到它才会调
# HomeCenterManager::processPresence(0x8d778c) → updateHomeCenterStatus(0x8d7b30)
# 把 HomeCenter.field_13 置 true、field_f 置 3；否则首页横幅永远显示「家庭中心离线」。
EVT_PRESENCE = 27


def new_uuid() -> str:
    return str(uuid.uuid4())


def build_message(oneof: int, payload: bytes, msg_id: str = None,
                  correlation_id: str = "", sender: str = "",
                  time_raw: bytes = None) -> bytes:
    """构造 Message 信封。time_raw 用于把请求里的 Time 原样回显。"""
    out = bytearray()
    out += enc_str(1, msg_id or new_uuid())
    if correlation_id:
        out += enc_str(2, correlation_id)
    if sender:
        out += enc_str(3, sender)
    if time_raw:
        out += enc_bytes(4, time_raw)
    out += enc_msg(oneof, payload)
    return bytes(out)


def parse_message(buf: bytes) -> dict:
    d = parse(buf)
    oneof = None
    payload = None
    for f in d:
        if 11 <= f <= 127:
            oneof, payload = f, d[f][0]
            break
    return {
        "MessageID": as_str(one(d, 1, b"")),
        "CorrelationID": as_str(one(d, 2, b"")),
        "Sender": as_str(one(d, 3, b"")),
        "Time_raw": one(d, 4, b""),
        "oneof": oneof,
        "payload": payload or b"",
        "raw": d,
    }


# ---------------------------------------------------------------- 具体消息


def build_on_off_request(entity_uuid: str, on: bool, timeout_ms: int = 0) -> bytes:
    b = enc_str(1, entity_uuid) + enc_repeated_uint(2, [1 if on else 0])
    if timeout_ms:
        b += enc_uint(3, timeout_ms)
    return b


def parse_on_off_request(buf: bytes) -> dict:
    d = parse(buf)
    cmds = ints(d, 2)
    return {"uuid": as_str(one(d, 1, b"")), "command": cmds[0] if cmds else None,
            "on": (cmds[0] == 1) if cmds else None,
            "timeout_ms": one(d, 3, 0)}


def build_on_off_result(status: int = 0) -> bytes:
    return enc_uint(1, status)


def parse_get_entity_request(buf: bytes) -> dict:
    d = parse(buf)
    return {
        "types": ints(d, 1),
        "commit": bool(one(d, 2, 0)),
        "count": one(d, 3, 0),
        "index": one(d, 4, 0),
        "filt_available": bool(one(d, 5, 0)),
        "include_remote": bool(one(d, 6, 0)),
        "ent_uuid": as_str(one(d, 7, b"")),
    }


def build_attribute(attr_id: int, int_value: int = None, str_value: str = None,
                    data_type: int = 0) -> bytes:
    b = enc_repeated_uint(1, [attr_id])
    if str_value is not None:
        b += enc_str(3, str_value)
    elif int_value is not None:
        b += enc_uint(2, int_value)
    b += enc_repeated_uint(6, [data_type])
    return b


def parse_attribute(buf: bytes) -> dict:
    d = parse(buf)
    ids = ints(d, 1)
    types = ints(d, 6)
    return {
        "attr_id": ids[0] if ids else None,
        "name": ATTR_ID.get(ids[0]) if ids else None,
        "int_value": one(d, 2, None),
        "str_value": as_str(one(d, 3, b"")) if 3 in d else None,
        "data_type": types[0] if types else 0,
    }


def build_physic_device(model: str, online: bool = True, available: bool = True) -> bytes:
    return enc_str(1, model) + enc_bool(2, online) + enc_bool(3, available)


def build_live_entity(uuid_: str, name: str, base_types, room_uuid: str = "",
                      attributes=None, model: str = None, online: bool = True,
                      extra=None) -> bytes:
    """base_types: EntityType 数值列表（设备=0 / 房间=2 / 场景=1）"""
    b = enc_repeated_uint(1, base_types)
    b += enc_str(2, uuid_)
    if name:
        b += enc_str(3, name)
    if room_uuid:
        b += enc_str(4, room_uuid)
    for a in (attributes or []):
        b += enc_msg(7, a)
    if model is not None:
        b += enc_msg(8, build_physic_device(model, online))
    if extra:
        b += extra
    return b


def parse_live_entity(buf: bytes) -> dict:
    d = parse(buf)
    attrs = [parse_attribute(x) for x in d.get(7, [])]
    dev = as_msg(one(d, 8, b""))
    return {
        "base_types": ints(d, 1),
        "uuid": as_str(one(d, 2, b"")),
        "name": as_str(one(d, 3, b"")),
        "room_uuid": as_str(one(d, 4, b"")),
        "attributes": attrs,
        "model": as_str(one(dev, 1, b"")) if dev else None,
        "online": bool(one(dev, 2, 0)) if dev else None,
        "is_room": 9 in d,
        "is_scene": 11 in d,
    }


# ---- 房间 / 场景实体 -------------------------------------------------
# LiveEntity.EntityRoom(9) 的 Dart 类型是 Room —— 空消息（BuilderInfo 无字段注册）
# LiveEntity.EntityScene(11) 的 Dart 类型是 Scene {1 Actions repeated}
# 因此房间名/场景名都挂在 LiveEntity.Name 上，子消息只作类型标记。

def build_room_entity(uuid_: str, name: str) -> bytes:
    """房间实体：BaseType=EntityRoom(2) + 空 Room 子消息"""
    return build_live_entity(uuid_, name, [2], extra=enc_msg(9, b""))


def build_scene_entity(uuid_: str, name: str, room_uuid: str = "",
                       on: bool = False) -> bytes:
    """场景实体：BaseType=EntityScene(1) + 空 Scene 子消息"""
    return build_live_entity(uuid_, name, [1], room_uuid=room_uuid,
                             extra=enc_msg(11, b""))


def build_set_scene_onoff_result(uuid_: str, onoff: bool, stage=None) -> bytes:
    """SetSceneOnOffResponse {1 UUID, 2 OnOff, 3 Stage(repeated enum)}"""
    b = enc_str(1, uuid_)
    b += enc_bool(2, bool(onoff))
    b += enc_repeated_uint(3, stage or [])
    return b


def parse_set_scene_onoff_request(buf: bytes) -> dict:
    d = parse(buf)
    return {"uuid": as_str(one(d, 1, b"")), "command": ints(d, 2)}


def build_get_entity_result(entities, count_remaining: int = 0) -> bytes:
    b = b"".join(enc_msg(1, e) for e in entities)
    if count_remaining:
        b += enc_uint(2, count_remaining)
    return b


def parse_get_entity_result(buf: bytes) -> dict:
    d = parse(buf)
    return {
        "entities": [parse_live_entity(x) for x in d.get(1, [])],
        "count_remaining": one(d, 2, 0),
    }


def build_write_attribute_result(code: int = 0) -> bytes:
    return enc_uint(1, code)


def build_read_attribute_result(code: int = 0, int_value=None,
                               str_value: str = None) -> bytes:
    """ReadAttributeResponse {1 Code, 2 Value, 3 ValueStr}
    —— 注意：一次只回一个属性值（App 每次请求也只带一个 AttrID），
       不是 repeated Attribute。"""
    b = enc_uint(1, code)
    if int_value is not None:
        b += enc_uint(2, int(int_value))
    if str_value:
        b += enc_str(3, str_value)
    return b


def build_cloud_server_result(api: str, ws: str, region: str = "CN",
                              encryption: bool = True, code: int = 0) -> bytes:
    b = enc_uint(1, code) + enc_bool(2, encryption)
    if region:
        b += enc_str(3, region)
    b += enc_str(4, api) + enc_str(5, ws)
    return b


def build_event(field: int, payload: bytes, sender: str = "",
                msg_id: str = None, time_raw: bytes = None) -> bytes:
    out = enc_str(1, msg_id or new_uuid())
    if sender:
        out += enc_str(2, sender)
    if time_raw:
        out += enc_bytes(3, time_raw)
    out += enc_msg(field, payload)
    return bytes(out)


def build_device_attr_report(entity_uuid: str, attributes) -> bytes:
    """DeviceAttrReportEvent：字段号未逐一实锤，按 (UUID, Attributes) 顺序编码。"""
    b = enc_str(1, entity_uuid)
    for a in attributes:
        b += enc_msg(2, a)
    return b


def build_on_off_status_changed(entity_uuid: str, on: bool) -> bytes:
    return enc_str(1, entity_uuid) + enc_bool(2, on)


def build_presence_event(online: bool, username: str, name: str = "",
                         group_id: str = "", group_name: str = "",
                         resource: str = "") -> bytes:
    """PresenceEvent（event.pb.dart）

    字段号（PROTO_FIELDNOS.json 实锤）：
      1 Username(string, = 家庭中心 uuid)
      2 Online(bool)
      3 Resource(string)
      4 Name(string)
      5 GroupID(string)
      6 GroupName(string)

    调用方必须再用 build_event(EVT_PRESENCE, ...) 包成 Event，
    发到主题 `event/<hc uuid>`（App 用 topic.split("/")[1] 找 HomeCenterCache，
    找不到就整条消息丢弃）。
    """
    b = enc_str(1, username) + enc_bool(2, bool(online))
    if resource:
        b += enc_str(3, resource)
    if name:
        b += enc_str(4, name)
    if group_id:
        b += enc_str(5, group_id)
    if group_name:
        b += enc_str(6, group_name)
    return b


# ---------------------------------------------------------------- 自测

if __name__ == "__main__":
    # 1. 信封往返
    req = build_message(MSG_ONOFF, build_on_off_request("abc-01", True), sender="app")
    m = parse_message(req)
    assert m["oneof"] == MSG_ONOFF and m["Sender"] == "app"
    r = parse_on_off_request(m["payload"])
    assert r == {"uuid": "abc-01", "command": 1, "on": True, "timeout_ms": 0}, r

    # 2. 实体往返
    ent = build_live_entity("2c11-01", "客厅阳台筒灯", [0], "area-0001",
                            [build_attribute(0, 1), build_attribute(61, 2700)],
                            model="TERNCY-WS01-D4")
    resp = build_message(MSG_GET_ENTITY_RESULT, build_get_entity_result([ent]),
                         correlation_id=m["MessageID"])
    got = parse_get_entity_result(parse_message(resp)["payload"])
    e = got["entities"][0]
    assert e["name"] == "客厅阳台筒灯" and e["model"] == "TERNCY-WS01-D4", e
    assert e["attributes"][0]["name"] == "on" and e["attributes"][0]["int_value"] == 1
    assert e["attributes"][1]["name"] == "colorTemperature"

    # 3. packed 兼容
    packed = _tag(1, 2) + varint(2) + varint(0) + varint(2)
    assert ints(parse(packed), 1) == [0, 2]

    print("terncy_proto 自测通过")
