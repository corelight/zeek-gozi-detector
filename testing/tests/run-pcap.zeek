# @TEST-DOC: Example of a test that runs Zeek on a pcap and verifies log content
# @TEST-EXEC: zeek -r $TRACES/2023-07-12-Gozi-infection-with-Cobalt-Strike.pcap $PACKAGE %INPUT >output
#
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: btest-diff gozi.log
# @TEST-EXEC: btest-diff notice.log
