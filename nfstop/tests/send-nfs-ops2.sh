TARGET="/mnt/foo"
ITERATIONS=100
FILES_PER_DIR=1

echo "NFS test starting on $TARGET"
echo "Iterations: $ITERATIONS"
echo "Files per dir: $FILES_PER_DIR"
echo

cd "$TARGET"


# Delay start of traffic to prevent testing misalignments with bpftrace scripts
sleep 1
echo "BEGIN NFS TRAFFIC"
echo

DIR="dir_$USER"
mkdir "$DIR"

# Create all the files
for f in $(seq 1 "$FILES_PER_DIR"); do
    FILE="$DIR/file_$f"
    echo "This is File $f" >> "$FILE"
done

# Write to each time $ITERATIONS number of times
for i in $(seq 1 "$ITERATIONS"); do

    for f in $DIR/*; do
        # echo "Iteration $i" >> "$f"
        m=""
        for j in $(seq 1 123456); do
            # m+="$j Elephant swinging in a rope...\n"
            m+="h"
        done
        echo "$m" >> "$f"
        sleep 0.1
    done

    echo "Completed iteration $i"
done

# Delete all
rm -rf "$DIR"

echo
echo "Done"