# Installation steps

change your current directory to to where the source and Makefile is located then issue:

```
git clone https://github.com/ahmedcs/IQM.git
cd IQM
cd KModule/
make
cd ..
cp OvS/* ~/openvswitch-2.4.0/datapath/
cd ~/openvswitch-2.4.0/datapath/
patch -p1 < iqm.patch
```

# OpenvSwitch version

You need to apply the patch that comes along with the source files to the "datapath" subfolder of the OpenvSwitch source directory. Notice that, the patch is customized to openvswitch version 2.4.0 and it may/may not work for other versions. If you are applying the patch to a different version, please read the patch file and update manually (few locations is updated).

The patch updates these files: (actions.c, datapath.c, datapath.h, Makefile.in, Module.mk)

Then you need to issue the patch command to patch (actions.c datapath.c, datapath.h, Makefile.in, Module.mk):

```
cd openvswitch-2.4.0/datapath
patch -p1 < iqm.patch
```

Copy the source files to the datapath folder (iqm.c and iqm.h), then we need to build and install the new openvswitch:

```
cd openvswtich-2.4.0
./configure --with-linux="/lib/modules/`uname -r`/build"
cd datapath
make clean
make
cd linux
sudo make modules_install
```

If the kernel module was not installed properly, it can be copied as follows (depending on the current location of the running OpenvSwitch):
```
cd openvswtich-2.4.0/datapath/linux
sudo cp openvswitch.ko /lib/modules/`uname -r`/kernel/net/openvswitch/openvswitch.ko
```

The location of the OpenvSwitch module can be found by the following:
```
modinfo openvswitch
```

# Kernel-Module Makefile update
If the source file has been changed, you need to update the name of the object file to match the new source file containing the module init_module and exit_module macros and the definition functions. SEE Makefile for more information.

Notice, you can include other source and header files but under the condition that there are a single source file containing the necessary init_module and exit_module macros and their function.


Now the output files is as follows:
```
iqm.o and iqm.ko
```
The file ending with .o is the object file while the one ending in .ko is the module file


# Run
To install the module into the kernel
```
sudo insmode iqm.ko
```
Now the module will do nothing until it is enabled by setting iqm_enable parameter as follows:   

```
sudo echo 1 > /sys/kernel/modules/iqm/parameters/iqm_enable;
```

Note that the parameters of the module are:  
1- iqm_enable: enable Incast detection module, 0 is the default which disables packet interception.  
2- M: the number of rounds before declaring incast.  
3- interval: the timer interval for the high resolution timer  

Also to call the module with different parameters issue the following:
```
sudo insmod iqm.ko iqm_enable=0 M=10 interval=200L;
```


# Stop

To stop the loss_probe module and free the resources issue the following command:

```
sudo rmmod -f iqm;
```

# For Simulation

Use the files in the NS2-simulations folder and copy them to a folder of your choice (e.g., queue or myqueue) in the NS2 source directory. 

Then add an entry in the source and header files in the MakeFile.in then configure and compile NS2. 

The next step is to design your own experiments, or wait until i upload the TCL scripts, anyways enjoy using the IQM system.

```
TODO: add the simulation scripts for various experiment scenarios
```
