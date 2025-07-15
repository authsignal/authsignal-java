package com.authsignal.model;

public class GetChallengeRequest extends ApiModel {
    public String challengeId;
    public String userId;
    public String action;
    public String verificationMethod;
}