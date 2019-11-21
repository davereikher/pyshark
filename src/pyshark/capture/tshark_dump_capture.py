import os

from pyshark.capture.capture import Capture


class TSharkDumpCapture(Capture):
    """A class representing a capture read from a dump of tshark's stdout."""

    def __init__(self, input_file=None, keep_packets=True, only_summaries=False,
                 use_json=False, eventloop=None, debug=False):
        """Creates a packet capture object by reading from file.

        :param keep_packets: Whether to keep packets after reading them via next(). Used to conserve memory when reading
        large caps (can only be used along with the "lazy" option!)
        :param input_file: File path of tshark's output
        :param only_summaries: Only produce packet summaries, much faster but includes very little information.
        :param use_json: Uses tshark in JSON mode (EXPERIMENTAL). It is a good deal faster than XML
        but also has less information. Available from Wireshark 2.2.0.
        """
        super(FileCapture, self).__init__(only_summaries=only_summaries,
                                          use_json=use_json, 
                                          eventloop=eventloop,
                                          debug=debug)
        self.input_filename = input_file
        if not isinstance(input_file, str):
            self.input_filename = input_file.name
        if not os.path.exists(self.input_filename):
            raise FileNotFoundError(
                    "[Errno 2] No such file or directory: "
                    + str(self.input_filename)
                    )
        self.keep_packets = keep_packets
#        self._packet_generator = self._packets_from_tshark_sync()
        self._packet_generator = self._packets_from_stdout()

    #TODO: change doc
    def _packets_from_tshark_sync():
        """Returns a generator of packets. 

        This is the sync version of packets_from_tshark. It wait for the completion of each coroutine and
         reimplements reading packets in a sync way, yielding each packet as it arrives.

        :param packet_count: If given, stops after this amount of packets is captured.
        """
        with open(self.input_filename, "r") as f:
            tshark_out = f.read()

        # NOTE: This has code duplication with the async version, think about how to solve this
        psml_structure, data = self.eventloop.run_until_complete(self._get_psml_struct(tshark_out)
        packets_captured = 0

        data = b""
        while True:
            try:
                packet, data = self.eventloop.run_until_complete(
                    self._get_packet_from_stream(tshark_out, data, psml_structure=psml_structure,
                                                 got_first_packet=packets_captured > 0))

            except EOFError:
                self._log.debug("EOF reached (sync)")
                break

            if packet:
                packets_captured += 1
                yield packet
            if packet_count and packets_captured >= packet_count:
                break

    def next(self):
        """Returns the next packet in the cap.

        If the capture's keep_packets flag is True, will also keep it in the internal packet list.
        """
        if not self.keep_packets:
            return self._packet_generator.send(None)
        elif self._current_packet >= len(self._packets):
            packet = self._packet_generator.send(None)
            self._packets += [packet]
        return super(TSharkDumpCapture, self).next_packet()

    def __getitem__(self, packet_index):
        if not self.keep_packets:
            raise NotImplementedError("Cannot use getitem if packets are not kept")
            # We may not yet have this packet
        while packet_index >= len(self._packets):
            try:
                self.next()
            except StopIteration:
                # We read the whole file, and there's still not such packet.
                raise KeyError("Packet of index %d does not exist in capture" % packet_index)
        return super(TSharkDumpCapture, self).__getitem__(packet_index)

#    def get_parameters(self, packet_count=None):
#        return super(FileCapture, self).get_parameters(packet_count=packet_count) + ["-r", self.input_filename]

    def __repr__(self):
        if self.keep_packets:
            return "<%s %s>" % (self.__class__.__name__, self.input_filename)
        else:
            return "<%s %s (%d packets)>" % (self.__class__.__name__, self.input_filename, len(self._packets))
