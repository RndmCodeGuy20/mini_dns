# dns_wire.cpp is pulled in directly from the firmware's main/ component
# (not linked as a library) so this test always exercises the exact same
# source that ships — see the header comment on ../CMakeLists.txt.
idf_component_register(SRCS "test_dns_wire.cpp" "../../main/dns_wire.cpp"
                    INCLUDE_DIRS "." "../../main"
                    REQUIRES unity)
