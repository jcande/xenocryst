CC := gcc
HARDEN := -D_FORTIFY_SOURCE=2 -fstack-protector-all
LDFLAGS := -Wl,--gc-sections -m32 -Wl,-z,relro,-z,now -fPIE -pie -fPIC $(HARDEN)
CFLAGS := -O3 -ffunction-sections -fdata-sections -m32 -std=gnu99 -Wall -DNDEBUG $(HARDEN)

bins := xenocryst

xenocryst_OBJS := xenocryst.o exec.o util.o gadgets.o tests.o

.PHONY: all clean

all: $(bins)
clean:
	$(RM) $(bins)
	$(RM) -r .obj

test: CFLAGS += -DTEST
test: all

debug: CFLAGS += -DDEBUG -g -ggdb -O
debug: all

# Dependencies tracking
$(foreach bin,$(bins),$(eval $(bin): $(addprefix .obj/,$($(bin)_OBJS))))

$(bins):
	$(LINK.o) -o $@ $^

src := $(wildcard *.c)
obj := $(src:%.c=.obj/%.o)
dep := $(src:%.c=.obj/%.d)

$(obj) $(dep): | .obj
.obj:
	mkdir $@
.obj/%.o: %.c
	$(COMPILE.c) -MMD -MP -o $@ $<

-include $(dep)
