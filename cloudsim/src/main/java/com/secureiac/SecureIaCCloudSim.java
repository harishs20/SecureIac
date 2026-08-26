package com.secureiac;

import org.cloudsimplus.brokers.DatacenterBrokerSimple;
import org.cloudsimplus.cloudlets.Cloudlet;
import org.cloudsimplus.cloudlets.CloudletSimple;
import org.cloudsimplus.core.CloudSimPlus;
import org.cloudsimplus.datacenters.Datacenter;
import org.cloudsimplus.datacenters.DatacenterSimple;
import org.cloudsimplus.hosts.Host;
import org.cloudsimplus.hosts.HostSimple;
import org.cloudsimplus.resources.Pe;
import org.cloudsimplus.resources.PeSimple;
import org.cloudsimplus.utilizationmodels.UtilizationModelDynamic;
import org.cloudsimplus.vms.Vm;
import org.cloudsimplus.vms.VmSimple;

import java.util.ArrayList;
import java.util.List;

public class SecureIaCCloudSim {

    public static void main(String[] args) {

        System.out.println("========================================");
        System.out.println("       SecureIaC - CloudSim Plus");
        System.out.println("========================================");

        // Create CloudSim Plus simulation
        CloudSimPlus simulation = new CloudSimPlus();

        // Create one datacenter with two hosts
        Datacenter datacenter = createDatacenter(simulation);

        // Create Datacenter Broker
        DatacenterBrokerSimple broker =
                new DatacenterBrokerSimple(simulation);

        // Create 3 VMs
        List<Vm> vmList = createVms();

        // Create 6 Cloudlets
        List<Cloudlet> cloudletList = createCloudlets();

        // Submit VMs and Cloudlets to the broker
        broker.submitVmList(vmList);
        broker.submitCloudletList(cloudletList);

        System.out.println();
        System.out.println("Starting simulation...");
        System.out.println();

        // Start simulation
        simulation.start();

        // Print Cloudlet results
        printResults(broker);

        // Print summary
        System.out.println();
        System.out.println("========================================");
        System.out.println("       SIMULATION COMPLETED");
        System.out.println("========================================");

        System.out.println("Datacenters         : 1");

        System.out.println(
                "Hosts               : "
                + datacenter.getHostList().size()
        );

        System.out.println(
                "VMs                 : "
                + vmList.size()
        );

        System.out.println(
                "Total Cloudlets     : "
                + cloudletList.size()
        );

        System.out.println(
                "Completed Cloudlets : "
                + broker.getCloudletFinishedList().size()
        );

        System.out.println("========================================");
    }


    /*
     * Creates one Datacenter containing two Hosts.
     */
    private static Datacenter createDatacenter(
            CloudSimPlus simulation) {

        List<Host> hostList = new ArrayList<>();

        // Host 1
        hostList.add(createHost());

        // Host 2
        hostList.add(createHost());

        return new DatacenterSimple(
                simulation,
                hostList
        );
    }


    /*
     * Creates a Host.
     *
     * Each Host has:
     * RAM      = 8 GB
     * Bandwidth = 10,000 Mbps
     * Storage   = 1,000,000 MB
     * CPU       = 4 cores
     * Each core = 1,000 MIPS
     */
    private static Host createHost() {

        long hostRam = 8192;
        long hostBw = 10000;
        long hostStorage = 1000000;
        long hostMips = 1000;

        int numberOfPes = 4;

        List<Pe> peList = new ArrayList<>();

        for (int i = 0; i < numberOfPes; i++) {
            peList.add(new PeSimple(hostMips));
        }

        return new HostSimple(
                hostRam,
                hostBw,
                hostStorage,
                peList
        );
    }


    /*
     * Creates 3 Virtual Machines.
     */
    private static List<Vm> createVms() {

        List<Vm> vmList = new ArrayList<>();

        // VM 1
        Vm vm1 = new VmSimple(0, 1000, 2);

        vm1.setRam(2048)
           .setBw(2000)
           .setSize(10000);


        // VM 2
        Vm vm2 = new VmSimple(1, 1000, 2);

        vm2.setRam(2048)
           .setBw(2000)
           .setSize(10000);


        // VM 3
        // FIXED: 1000 MIPS instead of 1500 MIPS
        Vm vm3 = new VmSimple(2, 1000, 2);

        vm3.setRam(4096)
           .setBw(3000)
           .setSize(15000);


        vmList.add(vm1);
        vmList.add(vm2);
        vmList.add(vm3);

        return vmList;
    }


    /*
     * Creates 6 Cloudlets / tasks.
     */
    private static List<Cloudlet> createCloudlets() {

        List<Cloudlet> cloudletList = new ArrayList<>();

        UtilizationModelDynamic utilization =
                new UtilizationModelDynamic(0.5);

        /*
         * Create 6 Cloudlets.
         *
         * Each Cloudlet has:
         * - Different workload length
         * - 2 required CPU cores
         */
        for (int i = 0; i < 6; i++) {

            long length = 10000 + (i * 2000);

            Cloudlet cloudlet =
                    new CloudletSimple(
                            i,
                            length,
                            2
                    );

            cloudlet
                    .setFileSize(1024)
                    .setOutputSize(1024)
                    .setUtilizationModelCpu(utilization)
                    .setUtilizationModelRam(utilization)
                    .setUtilizationModelBw(utilization);

            cloudletList.add(cloudlet);
        }

        return cloudletList;
    }


    /*
     * Prints execution results.
     */
    private static void printResults(
            DatacenterBrokerSimple broker) {

        List<Cloudlet> finishedCloudlets =
                broker.getCloudletFinishedList();

        System.out.println();

        System.out.println(
                "-----------------------------------------------------------------"
        );

        System.out.printf(
                "%-10s %-12s %-10s %-12s %-12s %-12s%n",
                "Cloudlet",
                "Status",
                "VM",
                "Start",
                "Finish",
                "Exec.Time"
        );

        System.out.println(
                "-----------------------------------------------------------------"
        );

        for (Cloudlet cloudlet : finishedCloudlets) {

            System.out.printf(
                    "%-10d %-12s %-10d %-12.2f %-12.2f %-12.2f%n",

                    cloudlet.getId(),

                    cloudlet.getStatus(),

                    cloudlet.getVm().getId(),

                    cloudlet.getStartTime(),

                    cloudlet.getFinishTime(),

                    cloudlet.getTotalExecutionTime()
            );
        }

        System.out.println(
                "-----------------------------------------------------------------"
        );
    }
}