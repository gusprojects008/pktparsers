DSAP = "dsap"
SSAP = "ssap"
CONTROL_FIELD = "control_field"
PID = "pid"

DSAP_FMT = "B"
SSAP_FMT = "B"
CONTROL_FIELD_FMT = "B"
PID_FMT = "H"

FMT = (
    "!" +
    DSAP_FMT +
    SSAP_FMT +
    CONTROL_FMT +
    OUI_FMT +
    PID_FMT
)
