#!/usr/bin/env bats

export LD_PRELOAD="${GENLB_LD_PRELOAD-$PWD/libglb.so}"
export GLB_OPTIONS="--round 7220 127.1.0.1:7120 127.2.0.1:7120"

@test "set up listeners" {
    timeout 60 cl 2 127.1.0.1 7120 &
    timeout 60 cl 2 127.2.0.1 7120 &
    timeout 60 cl 1 127.0.0.1 7220 &
}

@test "connect: both services listening" {
    run genlb nc -w 2 -z -vvv 127.0.0.1 7220

    [ "$status" -eq 0 ]
}

@test "connect: one service listening" {
    run genlb nc -w 2 -z -vvv 127.0.0.1 7220

    [ "$status" -eq 0 ]
}

@test "connect: dummy listener is still running" {
    run nc -w 2 -z -vvv 127.0.0.1 7220

    [ "$status" -eq 0 ]
}

@test "connect: no services listening" {
    run genlb nc -w 2 -z -vvv 127.0.0.1 7220

    [ "$status" -ne 0 ]
}
