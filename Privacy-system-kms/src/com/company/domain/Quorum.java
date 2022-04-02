package com.company.domain;

import java.util.LinkedList;

public class Quorum {
    private Integer size;
    private LinkedList<String> operators_set;

    // ---------------------------------------------------------------------

    public Quorum(){

    }

    // ---------------------------------------------------------------------


    public Integer getSize() {
        return size;
    }

    public void setSize(Integer size) {
        this.size = size;
    }

    public LinkedList<String> getOperatorsSet() {
        return operators_set;
    }

    public void setOperatorsSet(LinkedList<String> operators_set) {
        this.operators_set = operators_set;
    }
}
