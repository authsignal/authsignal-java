package com.authsignal.model;

public class FlowAction extends ApiModel {
    public FlowState state;
    public CompletedActionStep[] completedSteps;
    public ActionStep nextStep;
}
