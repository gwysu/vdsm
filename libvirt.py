#!/usr/bin/python


start_needed_srv() {
    local srv
    local ret_val

    for srv in $NEEDED_SERVICES
    do
        if ! /sbin/service $srv status > /dev/null 2>&1;
        then
            echo "Starting $srv..."
            /sbin/service $srv start
            ret_val=$?
            if [ $ret_val -ne 0 ]
            then
                log_failure_msg "$prog: Dependent $srv failed to start"
                return $ret_val
            fi
        fi
    done

    /sbin/service iscsid force-start
}

def test_lo():
{
    env = os.environ.copy()
    
    env.update({"LC_ALL": "C"})

    sort_cmd = ["sort",
              "-k1,1",


    subprocess.call(sort_cmd, env = env)

    if ! LC_ALL=C /sbin/ifconfig lo | /bin/grep -q UP;
    then
        log_failure_msg "VDSMD: lo interface is down, can't run !"
        echo "VDSMD: lo interface is down, can't run !" > /dev/kmsg
        return 1
    fi
    return 0
}

free_space() {