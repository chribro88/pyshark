import json
import os

from pyshark.tshark.output_parser.base_parser import BaseTsharkOutputParser

try:
    import ujson
    USE_UJSON = True
except ImportError:
    USE_UJSON = False

from pyshark.packet.layers.ek_layer import EkLayer
from pyshark.packet.packet import Packet

_ENCODED_OS_LINESEP = os.linesep.encode()


class TsharkEkJsonParser(BaseTsharkOutputParser):

    def _parse_single_packet(self, packet):
        return packet_from_ek_packet(packet)

    def _extract_packet_from_data(self, data, got_first_packet=True):
        """Returns a packet's data and any remaining data after reading that first packet"""
        start_index = 0
        data = data.lstrip()
        if data.startswith(b'{"ind'):
            # Skip the 'index' JSONs, generated for Elastic.
            # See: https://bugs.wireshark.org/bugzilla/show_bug.cgi?id=16656
            start_index = data.find(_ENCODED_OS_LINESEP) + 1
        linesep_location = data.find(_ENCODED_OS_LINESEP, start_index)
        if linesep_location == -1:
            return None, data

        return data[start_index:linesep_location], data[linesep_location + 1:]


def is_data_ek_layer(layer_data):
    # normal layer, single
    if isinstance(layer_data, dict):
        return True
    
    # raw layer
    elif isinstance(layer_data, str):
        return True
    
    # segment layer, multiple raw layer
    elif isinstance(layer_data, list) and all(isinstance(item, str) for item in layer_data):
        return True
    
    # mutliple regular layer
    return False


def get_first_layer(layer_name, layer_data):
    # Check Layer can be parsed
    if is_data_ek_layer(layer_data): 
        return EkLayer(layer_name, layer_data), None
    
    # Layer is nested
    else:
        layer_data_ = layer_data.pop(0)
        return EkLayer(layer_name, layer_data_), layer_data


def packet_from_ek_packet(json_pkt):
    if USE_UJSON:
        pkt_dict = ujson.loads(json_pkt)
    else:
        pkt_dict = json.loads(json_pkt.decode('utf-8'))

    # We use the frame dict here and not the object access because it's faster.
    frame_dict = pkt_dict['layers'].pop('frame')
    layers = []
    for layer_name in frame_dict['frame_frame_protocols'].split(':'):
        layer_data = pkt_dict['layers'].pop(layer_name, None)
        if layer_data is not None:
            ek_layer, layer_data = get_first_layer(layer_name, layer_data)
            layers.append(ek_layer)
                
            # If any layer remaining add back to pkt_dict 
            # - attempt to keep layers in same order as frame proto
            # - though layer count in frame proto and pkt_dict not always match
            # - if frame proto count < pkt_dict count, then will parse in leftovers
            if layer_data != []:
                # add to beginning of layer_dict, keep leftovers at end
                pkt_dict['layers'] = {**{layer_name: layer_data}, **pkt_dict['layers']}

             
    # Add all leftovers
    for layer_name, layer_data in pkt_dict['layers'].items():
        # refactored names to keep consistent
        # some layers in pkt_dict are None (e.g. 'tcp_tcp_segments') - tshark not parse properly?
        while layer_data not in (None, []):
            ek_layer, layer_data = get_first_layer(layer_name, layer_data)
            layers.append(ek_layer)

    return Packet(layers=layers, frame_info=EkLayer('frame', frame_dict),
                  number=int(frame_dict.get('frame_frame_number', 0)),
                  length=int(frame_dict['frame_frame_len']),
                  sniff_time=frame_dict['frame_frame_time_epoch'],
                  interface_captured=frame_dict.get('rame_frame_interface_id'))
