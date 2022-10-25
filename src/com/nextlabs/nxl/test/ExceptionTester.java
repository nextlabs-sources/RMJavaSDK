package com.nextlabs.nxl.test;

public class ExceptionTester {

    public static void main(String[] args) {
        try {
            A();
            B();
            C();
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }

    private static void A() throws Exception {
        B();
        System.out.println("After A()");
    }

    private static void B() throws Exception {
        C();
        System.out.println("After B()");
    }

    private static void C() throws Exception {
        int a = 3 / 0;
        System.out.println("After C()");
    }
}
