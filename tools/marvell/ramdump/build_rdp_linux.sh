gcc -o rdp -w -lstdc++ utils.cpp rdp.cpp i2c-logger.cpp pmlog.cpp \
emmd_elf.cpp printk.cpp logcat_logger.cpp
gcc -o printk -D STAND_ALONE -w -lstdc++ utils.cpp printk.cpp
