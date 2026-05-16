SUMMARY_ANALYZERS_DISPATCH = {
    "dot11": dot11.parsers.summary.analyzer
}

class TrafficContext:
    def __init__(self, dlt: str | int):

        self.dlt = dlt

        self.summary = TrafficSummary()

    def update(summaries: dict[str, Any]):
        self.summary.total_packets += 1
        for protocol, protocols_summaries in summaries.items():
            summary_analyzer = SUMMARY_ANALYSER_DISPATCH.get(protocol)
            for protocol_summary in protocols_summaries:
                summary_analyzer(protocol, protocol_summary, self.summary)
