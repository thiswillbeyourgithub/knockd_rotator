import java.security.MessageDigest
import java.time.Instant
import java.time.ZoneOffset
import kotlin.math.log2
import kotlin.system.exitProcess

/**
 * Object responsible for generating knock sequences compatible with knockd-rotator.
 *
 * This object encapsulates the logic for generating time-based, secret-dependent
 * port knocking sequences. It can be configured via parameters passed to its
 * generation function, making it suitable for embedding in applications like Android apps.
 */
object KnockdRotatorGenerator {

    // Default configuration values (matching the Python script)
    const val DEFAULT_SEQUENCE_LENGTH = 10
    const val DEFAULT_PROTO_MODULO = 0 // 0 means always TCP
    const val DEFAULT_PERIOD_MODULO = 21600 // 6 hours in seconds
    const val DEFAULT_PORTS_STRING = "2000-65536"
    const val MIN_ENTROPY_BITS = 40.0

    /**
     * Parses a port string (e.g., "2000-65535,8080") into a sorted list of unique integers.
     *
     * @param portStr The string representation of ports.
     * @return A sorted list of unique port numbers.
     * @throws IllegalArgumentException if the format is invalid, ports are duplicated,
     *         or fewer than 2 ports are specified.
     */
    fun parsePorts(portStr: String): List<Int> {
        val ports = mutableSetOf<Int>()
        try {
            portStr.split(",").forEach { part ->
                val trimmedPart = part.trim()
                if (trimmedPart.contains("-")) {
                    val range = trimmedPart.split("-", limit = 2)
                    val start = range[0].toInt()
                    val end = range[1].toInt()
                    if (start > end) throw IllegalArgumentException("Invalid range: $start > $end")
                    (start..end).forEach { ports.add(it) }
                } else if (trimmedPart.isNotEmpty()) {
                    ports.add(trimmedPart.toInt())
                }
            }
        } catch (e: NumberFormatException) {
            throw IllegalArgumentException("Invalid port format in '$portStr'. ${e.message}", e)
        }

        if (ports.size < 2) {
            throw IllegalArgumentException("KNOCKD_ROTATOR_PORTS must contain at least 2 unique ports (found ${ports.size})")
        }

        // Warn if 3 or fewer ports (can be handled by the caller if needed)
        // if (ports.size <= 3) {
        //     System.err.println("Warning: Only ${ports.size} ports available. This significantly reduces security.")
        // }

        return ports.toList().sorted()
    }

    /**
     * Calculates the entropy of a knock sequence in bits.
     *
     * Entropy = sequence_length * log2(port_count)
     *
     * @param sequenceLength Length of the knock sequence.
     * @param portCount Number of possible ports to choose from.
     * @return Entropy in bits. Returns 0.0 if portCount <= 1.
     */
    fun calculateKnockEntropy(sequenceLength: Int, portCount: Int): Double {
        if (portCount <= 1) {
            return 0.0
        }
        return sequenceLength * log2(portCount.toDouble())
    }

    /**
     * Calculates the shared seed based on the current time period with an optional offset.
     * The seed is derived from the start of the current UTC time period defined by periodModulo.
     *
     * @param periodModulo The duration of each period in seconds.
     * @param offset Integer offset to shift the period (negative for past, positive for future). Default is 0.
     * @return The calculated seed value (Unix timestamp of the period start).
     * @throws IllegalStateException if the calculated period start is zero.
     */
    fun calculateSharedSeed(periodModulo: Int, offset: Int = 0): Long {
        // Get current UTC timestamp in seconds
        val currentTimestamp = Instant.now().epochSecond
        // Calculate the start of the relevant period
        val periodStart = ((currentTimestamp / periodModulo) + offset) * periodModulo

        // Basic sanity checks matching Python/Zsh scripts
        if (periodStart == 0L) {
            throw IllegalStateException("Calculated period start is zero. Check periodModulo ($periodModulo) and system time.")
        }
        if (periodStart.toString().length <= 5) {
            // Log warning instead of throwing error for potentially valid short timestamps
            System.err.println("Warning: Suspiciously short period start value: $periodStart")
        }
        return periodStart
    }

    /**
     * Generates a formatted knock sequence for a specific service based on configuration.
     *
     * This is the core logic, designed to be easily called from other Kotlin/Java code.
     *
     * @param serviceName The name of the service (e.g., "ssh"). "_ROTATOR" will be appended if missing.
     * @param offset Time period offset (default: 0).
     * @param sequenceLength The number of ports in the sequence.
     * @param secret The shared secret string (must be >= 10 chars).
     * @param protoModulo Determines protocol (0=always TCP, >0=port%modulo even=TCP, odd=UDP).
     * @param periodModulo How often the sequence changes (seconds).
     * @param ports The list of available ports to choose from (must have >= 2).
     * @return Formatted sequence string (e.g., "1234:tcp 5678:udp 9012:tcp").
     * @throws IllegalArgumentException if configuration is invalid (e.g., short secret, insufficient ports, low entropy).
     */
    @Throws(IllegalArgumentException::class)
    fun generateKnockSequence(
        serviceName: String,
        offset: Int = 0,
        sequenceLength: Int,
        secret: String,
        protoModulo: Int,
        periodModulo: Int,
        ports: List<Int>
    ): String {
        // --- Input Validations ---
        if (sequenceLength < 5) {
            throw IllegalArgumentException("Sequence length must be at least 5.")
        }
        if (secret.length < 10) {
            throw IllegalArgumentException("Secret must be at least 10 characters long.")
        }
        if (ports.size < 2) {
            // This should ideally be caught by parsePorts, but double-check
            throw IllegalArgumentException("Must have at least 2 ports available.")
        }
        // Validate port range (basic check, assumes parsePorts did thorough validation)
        ports.forEach {
             if (it < 1 || it > 65535) throw IllegalArgumentException("Port $it is outside valid range (1-65535)")
        }


        // --- Entropy Check ---
        val entropyBits = calculateKnockEntropy(sequenceLength, ports.size)
        if (entropyBits < MIN_ENTROPY_BITS) {
            val errorMsg = String.format(
                "Insufficient entropy: %.2f bits. Required minimum: %.0f bits. Increase sequence length or add more ports.",
                entropyBits, MIN_ENTROPY_BITS
            )
            // Log warning, but throw exception to match Python's behavior on insufficient entropy
             System.err.println("Warning: $errorMsg")
            throw IllegalArgumentException(errorMsg)
        }

        // --- Sequence Generation ---

        // Ensure service_name ends with _ROTATOR
        val actualServiceName = if (serviceName.endsWith("_ROTATOR")) serviceName else "${serviceName}_ROTATOR"

        // Calculate seed for the target period
        val currentSeed = calculateSharedSeed(periodModulo, offset)

        // Create the service-specific seed string
        val sectionSeed = "$currentSeed$actualServiceName$secret"

        // Prepare SHA-256 hasher
        val digest = MessageDigest.getInstance("SHA-256")

        val generatedPorts = mutableListOf<Int>()
        for (i in 1..sequenceLength) {
            // Generate hash from seed + iteration number
            val hashInput = "$sectionSeed$i".toByteArray(Charsets.UTF_8)
            val hashBytes = digest.digest(hashInput)

            // Take first 4 bytes (8 hex chars) and convert to Long, then Int
            // Need to handle potential sign extension when converting bytes to Int/Long
            var decimalValue: Long = 0
            for (j in 0..3) {
                // Treat byte as unsigned by masking with 0xFF before shifting
                decimalValue = (decimalValue shl 8) or (hashBytes[j].toLong() and 0xFF)
            }

            // Select a port from the list using modulo
            // Use toInt() safely as the index won't exceed list size which is Int range
            // Use absolute value of modulo result in case decimalValue is negative after conversion
            // (though with the unsigned conversion above, it shouldn't be)
            val portIndex = (decimalValue % ports.size).toInt().let { if (it < 0) it + ports.size else it }
            val port = ports[portIndex]
            generatedPorts.add(port)
        }

        // Format the sequence with protocol determination
        val sequenceParts = generatedPorts.map { port ->
            val protocol = if (protoModulo == 0) {
                "tcp"
            } else {
                if (port % protoModulo == 0) "tcp" else "udp"
            }
            "$port:$protocol"
        }

        return sequenceParts.joinToString(" ")
    }
}

/**
 * Main function for command-line execution to generate a knock sequence.
 * Reads configuration from environment variables and arguments.
 * This allows verifying the Kotlin implementation against the Python/Zsh scripts.
 *
 * Usage:
 *   kotlin KnockdRotatorClient.kt generate <service_name> [--offset N]
 *
 * Environment Variables:
 *   KNOCKD_ROTATOR_LENGTH (optional, default 10)
 *   KNOCKD_ROTATOR_SECRET (required, min 10 chars)
 *   KNOCKD_ROTATOR_PROTO_MODULO (optional, default 0)
 *   KNOCKD_ROTATOR_PERIOD_MODULO (optional, default 21600)
 *   KNOCKD_ROTATOR_PORTS (optional, default "2000-65536")
 */
fun main(args: Array<String>) {
    // --- Configuration from Environment Variables ---
    val sequenceLength = System.getenv("KNOCKD_ROTATOR_LENGTH")?.toIntOrNull()
        ?: KnockdRotatorGenerator.DEFAULT_SEQUENCE_LENGTH
    val secret = System.getenv("KNOCKD_ROTATOR_SECRET")
    val protoModulo = System.getenv("KNOCKD_ROTATOR_PROTO_MODULO")?.toIntOrNull()
        ?: KnockdRotatorGenerator.DEFAULT_PROTO_MODULO
    val periodModulo = System.getenv("KNOCKD_ROTATOR_PERIOD_MODULO")?.toIntOrNull()
        ?: KnockdRotatorGenerator.DEFAULT_PERIOD_MODULO
    val portStr = System.getenv("KNOCKD_ROTATOR_PORTS")
        ?: KnockdRotatorGenerator.DEFAULT_PORTS_STRING

    // --- Basic Environment Variable Validation ---
    if (secret == null) {
        System.err.println("Error: KNOCKD_ROTATOR_SECRET environment variable must be set")
        exitProcess(1)
    }
     if (secret.length < 10) {
         System.err.println("Error: KNOCKD_ROTATOR_SECRET must be at least 10 characters long")
         exitProcess(1)
     }
    if (sequenceLength < 5) {
        System.err.println("Error: KNOCKD_ROTATOR_LENGTH must be at least 5")
        exitProcess(1)
    }
    // Check if default period modulo is used without explicit setting
    if (System.getenv("KNOCKD_ROTATOR_PERIOD_MODULO") == null && periodModulo == KnockdRotatorGenerator.DEFAULT_PERIOD_MODULO) {
         System.err.println("Warning: KNOCKD_ROTATOR_PERIOD_MODULO not set, using default of ${KnockdRotatorGenerator.DEFAULT_PERIOD_MODULO} (${KnockdRotatorGenerator.DEFAULT_PERIOD_MODULO / 3600} hours)")
    }


    // --- Parse Ports ---
    val ports: List<Int>
    try {
        ports = KnockdRotatorGenerator.parsePorts(portStr)
    } catch (e: IllegalArgumentException) {
        System.err.println("Error parsing KNOCKD_ROTATOR_PORTS: ${e.message}")
        exitProcess(1)
    }
     // Warn if few ports
     if (ports.size <= 3) {
         System.err.println("Warning: Only ${ports.size} ports available. This significantly reduces security.")
     }


    // --- Argument Parsing (Simple) ---
    var serviceName: String? = null
    var offset = 0
    var mode: String? = null

    val argList = args.toMutableList()

    // Very basic argument parsing for 'generate' mode and '--offset'
    if (argList.isNotEmpty() && (argList[0] == "generate" || argList[0] == "gen")) {
        mode = "generate"
        argList.removeAt(0) // Consume mode

        val offsetIndex = argList.indexOf("--offset")
        if (offsetIndex != -1 && offsetIndex + 1 < argList.size) {
            try {
                offset = argList[offsetIndex + 1].toInt()
                // Remove offset flag and value
                argList.removeAt(offsetIndex)
                argList.removeAt(offsetIndex)
            } catch (e: NumberFormatException) {
                System.err.println("Error: Invalid value for --offset: ${argList[offsetIndex + 1]}")
                exitProcess(1)
            }
        }

        if (argList.size == 1) {
            serviceName = argList[0]
        }
    }

    if (mode != "generate" || serviceName == null) {
        System.err.println("Usage: kotlin KnockdRotatorClient.kt generate <service_name> [--offset N]")
        System.err.println("  (Reads configuration from KNOCKD_ROTATOR_* environment variables)")
        exitProcess(1)
    }

    // --- Calculate and Display Entropy ---
    val entropyBits = KnockdRotatorGenerator.calculateKnockEntropy(sequenceLength, ports.size)
    println(String.format("Knock sequence entropy: %.2f bits", entropyBits))
    if (entropyBits < KnockdRotatorGenerator.MIN_ENTROPY_BITS) {
        System.err.println(String.format("WARNING: Current configuration has low entropy (%.2f bits)", entropyBits))
        System.err.println(String.format("Minimum recommended entropy: %.0f bits", KnockdRotatorGenerator.MIN_ENTROPY_BITS))
        // Note: Generation will fail later if entropy is too low, but we warn here too.
    }


    // --- Generate and Print Sequence ---
    try {
        val sequence = KnockdRotatorGenerator.generateKnockSequence(
            serviceName = serviceName,
            offset = offset,
            sequenceLength = sequenceLength,
            secret = secret, // Already checked for null
            protoModulo = protoModulo,
            periodModulo = periodModulo,
            ports = ports
        )
        println(sequence) // Print the generated sequence to standard output
    } catch (e: IllegalArgumentException) {
        System.err.println("Error generating sequence: ${e.message}")
        exitProcess(1)
    } catch (e: IllegalStateException) {
        System.err.println("Error calculating seed: ${e.message}")
        exitProcess(1)
    } catch (e: Exception) {
        System.err.println("An unexpected error occurred: ${e.message}")
        e.printStackTrace() // Print stack trace for unexpected errors
        exitProcess(1)
    }
}
