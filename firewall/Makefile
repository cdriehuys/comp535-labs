obj-m += filter.o

all:
	make -C /lib/module/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/module/$(shell uname -r)build M=$(PWD) clean
