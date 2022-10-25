package com.nextlabs.nxl.pojos;

public class ConnectionResultWrapper {

    private ConnectionResult connectionResult = ConnectionResult.CONNECTION_ERROR;

    public ConnectionResult getConnectionResult() {
        return connectionResult;
    }

    public void setConnectionResult(ConnectionResult connectionResult) {
        this.connectionResult = connectionResult;
    }
}
