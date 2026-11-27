#!/bin/sh
# build1-8+ does not propagate the exit status of "ant build"; fail the job
# when any ant invocation recorded in the log failed.
LOG="$1"
tail -n 40 "$LOG"
if grep -q "BUILD FAILED" "$LOG"; then
  echo "ant build failed:"
  grep -n -B 30 "BUILD FAILED" "$LOG" | head -n 200
  exit 1
fi
if [ ! -f build/artifacts/jdk1.8/jars/bcprov-jdk18on-176.jar ]; then
  echo "bcprov-jdk18on jar was not produced"
  exit 1
fi
ls -l build/artifacts/jdk1.8/jars/
