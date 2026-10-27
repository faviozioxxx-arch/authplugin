package ru.auth;

import io.papermc.paper.event.player.AsyncChatEvent;
import net.kyori.adventure.text.Component;
import net.kyori.adventure.text.format.NamedTextColor;
import net.kyori.adventure.title.Title;
import org.bukkit.Bukkit;
import org.bukkit.GameMode;
import org.bukkit.Location;
import org.bukkit.World;
import org.bukkit.WorldCreator;
import org.bukkit.command.Command;
import org.bukkit.command.CommandExecutor;
import org.bukkit.command.CommandSender;
import org.bukkit.configuration.file.YamlConfiguration;
import org.bukkit.entity.Player;
import org.bukkit.event.EventHandler;
import org.bukkit.event.EventPriority;
import org.bukkit.event.Listener;
import org.bukkit.event.entity.EntityDamageEvent;
import org.bukkit.event.entity.EntityPickupItemEvent;
import org.bukkit.event.player.PlayerCommandPreprocessEvent;
import org.bukkit.event.player.PlayerDropItemEvent;
import org.bukkit.event.player.PlayerInteractEvent;
import org.bukkit.event.player.PlayerJoinEvent;
import org.bukkit.event.player.PlayerQuitEvent;
import org.bukkit.generator.ChunkGenerator;
import org.bukkit.plugin.java.JavaPlugin;
import org.bukkit.scheduler.BukkitRunnable;
import org.bukkit.scheduler.BukkitTask;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.Locale;
import java.util.Map;
import java.util.Random;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Регистрация и логин. Пока игрок не авторизован, он падает в бездну
 * (отдельный пустой мир), не получает урона, а через 60 секунд кикается.
 */
public final class AuthPlugin extends JavaPlugin implements Listener, CommandExecutor {

    private static final int AUTH_TIMEOUT_SECONDS = 60;
    private static final int MAX_LOGIN_ATTEMPTS = 3;
    private static final int MIN_PASSWORD_LENGTH = 4;
    private static final int MAX_PASSWORD_LENGTH = 64;
    private static final int PBKDF2_ITERATIONS = 65_536;
    private static final double VOID_SPAWN_Y = 300.0;
    private static final String VOID_WORLD_NAME = "auth_void";
    private static final Set<String> ALLOWED_COMMANDS = Set.of("register", "reg", "login", "l");
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Set<UUID> unauthenticated = ConcurrentHashMap.newKeySet();
    private final Set<UUID> busy = ConcurrentHashMap.newKeySet();
    private final Map<UUID, Integer> attempts = new ConcurrentHashMap<>();
    private final Map<UUID, GameMode> savedModes = new ConcurrentHashMap<>();
    private final Map<UUID, BukkitTask> timers = new ConcurrentHashMap<>();

    private File dataFile;
    private YamlConfiguration data;
    private World voidWorld;
    private BukkitTask voidKeeper;

    // ------------------------------------------------------------------ lifecycle

    @Override
    public void onEnable() {
        getDataFolder().mkdirs();
        dataFile = new File(getDataFolder(), "players.yml");
        data = YamlConfiguration.loadConfiguration(dataFile);

        WorldCreator creator = new WorldCreator(VOID_WORLD_NAME);
        creator.generator(new VoidGenerator());
        creator.generateStructures(false);
        voidWorld = creator.createWorld();
        if (voidWorld == null) {
            getLogger().severe("Не удалось создать мир " + VOID_WORLD_NAME + ", плагин отключён.");
            getServer().getPluginManager().disablePlugin(this);
            return;
        }
        voidWorld.setSpawnLocation(0, 100, 0);
        voidWorld.setTime(6000);

        getCommand("register").setExecutor(this);
        getCommand("login").setExecutor(this);
        getServer().getPluginManager().registerEvents(this, this);

        // Не даём неавторизованным игрокам упасть насмерть: когда они долетают
        // до низа, возвращаем их наверх, чтобы падение было бесконечным.
        voidKeeper = getServer().getScheduler().runTaskTimer(this, this::keepPlayersFalling, 5L, 5L);

        // На случай /reload — всех онлайн считаем неавторизованными.
        for (Player player : Bukkit.getOnlinePlayers()) {
            startAuth(player);
        }
    }

    @Override
    public void onDisable() {
        if (voidKeeper != null) {
            voidKeeper.cancel();
        }
        for (BukkitTask task : timers.values()) {
            task.cancel();
        }
        timers.clear();
        for (UUID id : Set.copyOf(unauthenticated)) {
            Player player = Bukkit.getPlayer(id);
            if (player != null) {
                restoreAndLeaveVoid(player);
            }
        }
        unauthenticated.clear();
    }

    // ------------------------------------------------------------------ auth flow

    private void startAuth(Player player) {
        UUID id = player.getUniqueId();
        unauthenticated.add(id);
        attempts.remove(id);
        savedModes.putIfAbsent(id, player.getGameMode());

        player.setGameMode(GameMode.SURVIVAL);
        player.setAllowFlight(false);
        player.setFlying(false);
        player.teleport(voidLocation(player));
        player.setFallDistance(0f);

        startTimer(id);
    }

    private void startTimer(UUID id) {
        cancelTimer(id);
        BukkitTask task = new BukkitRunnable() {
            int remaining = AUTH_TIMEOUT_SECONDS;
            boolean first = true;

            @Override
            public void run() {
                Player player = Bukkit.getPlayer(id);
                if (player == null || !unauthenticated.contains(id)) {
                    cancel();
                    timers.remove(id);
                    return;
                }
                if (remaining <= 0) {
                    cancel();
                    timers.remove(id);
                    player.kick(Component.text("Время на авторизацию истекло (" + AUTH_TIMEOUT_SECONDS + " сек.)",
                            NamedTextColor.RED));
                    return;
                }

                boolean registered = isRegistered(id);
                String hint = registered ? "/login (пароль)" : "/register (пароль)";

                if (first) {
                    first = false;
                    player.showTitle(Title.title(
                            Component.text(registered ? "Вход" : "Регистрация", NamedTextColor.GOLD),
                            Component.text("Напишите " + hint, NamedTextColor.YELLOW),
                            Title.Times.times(Duration.ofMillis(500), Duration.ofSeconds(remaining), Duration.ofSeconds(1))
                    ));
                }
                if (remaining % 10 == 0) {
                    player.sendMessage(Component.text("Напишите " + hint, NamedTextColor.YELLOW));
                }
                player.sendActionBar(Component.text("Напишите " + hint + "  |  осталось " + remaining + " сек.",
                        NamedTextColor.GOLD));
                remaining--;
            }
        }.runTaskTimer(this, 10L, 20L);
        timers.put(id, task);
    }

    private void cancelTimer(UUID id) {
        BukkitTask task = timers.remove(id);
        if (task != null) {
            task.cancel();
        }
    }

    /** Игрок успешно вошёл/зарегистрировался: снимаем ограничения и отправляем на спавн. */
    private void authenticate(Player player) {
        UUID id = player.getUniqueId();
        unauthenticated.remove(id);
        attempts.remove(id);
        cancelTimer(id);

        player.clearTitle();
        player.sendActionBar(Component.empty());
        restoreAndLeaveVoid(player);

        // Выходим из бездны сразу (на случай, если /spawn с задержкой), затем вызываем /spawn.
        getServer().getScheduler().runTask(this, () -> {
            if (player.isOnline()) {
                player.performCommand("spawn");
            }
        });
    }

    private void restoreAndLeaveVoid(Player player) {
        GameMode mode = savedModes.remove(player.getUniqueId());
        if (mode != null) {
            player.setGameMode(mode);
        }
        player.setFallDistance(0f);
        player.teleport(mainSpawn());
    }

    private void keepPlayersFalling() {
        for (UUID id : unauthenticated) {
            Player player = Bukkit.getPlayer(id);
            if (player == null) {
                continue;
            }
            Location loc = player.getLocation();
            if (loc.getWorld() != voidWorld || loc.getY() < 0) {
                player.teleport(voidLocation(player));
                player.setFallDistance(0f);
            }
        }
    }

    private Location voidLocation(Player player) {
        Location current = player.getLocation();
        return new Location(voidWorld, 0.5, VOID_SPAWN_Y, 0.5, current.getYaw(), current.getPitch());
    }

    private Location mainSpawn() {
        return Bukkit.getWorlds().get(0).getSpawnLocation().add(0.5, 0, 0.5);
    }

    // ------------------------------------------------------------------ commands

    @Override
    public boolean onCommand(CommandSender sender, Command command, String label, String[] args) {
        if (!(sender instanceof Player player)) {
            sender.sendMessage("Эта команда только для игроков.");
            return true;
        }
        if (!unauthenticated.contains(player.getUniqueId())) {
            send(player, NamedTextColor.GREEN, "Вы уже авторизованы.");
            return true;
        }
        if (command.getName().equalsIgnoreCase("register")) {
            handleRegister(player, args);
        } else {
            handleLogin(player, args);
        }
        return true;
    }

    private void handleRegister(Player player, String[] args) {
        UUID id = player.getUniqueId();
        if (isRegistered(id)) {
            send(player, NamedTextColor.RED, "Вы уже зарегистрированы. Напишите /login (пароль)");
            return;
        }
        if (args.length != 1) {
            send(player, NamedTextColor.RED, "Используйте: /register (пароль)");
            return;
        }
        String password = args[0];
        if (password.length() < MIN_PASSWORD_LENGTH || password.length() > MAX_PASSWORD_LENGTH) {
            send(player, NamedTextColor.RED, "Длина пароля — от " + MIN_PASSWORD_LENGTH + " до "
                    + MAX_PASSWORD_LENGTH + " символов.");
            return;
        }
        if (!busy.add(id)) {
            return;
        }

        getServer().getScheduler().runTaskAsynchronously(this, () -> {
            byte[] salt = new byte[16];
            RANDOM.nextBytes(salt);
            byte[] hash;
            try {
                hash = hash(password, salt);
            } catch (RuntimeException ex) {
                getLogger().severe("Ошибка хеширования пароля: " + ex);
                getServer().getScheduler().runTask(this, () -> {
                    busy.remove(id);
                    send(player, NamedTextColor.RED, "Внутренняя ошибка, попробуйте ещё раз.");
                });
                return;
            }
            getServer().getScheduler().runTask(this, () -> {
                busy.remove(id);
                if (!player.isOnline() || !unauthenticated.contains(id)) {
                    return;
                }
                String path = "players." + id;
                data.set(path + ".name", player.getName());
                data.set(path + ".salt", Base64.getEncoder().encodeToString(salt));
                data.set(path + ".hash", Base64.getEncoder().encodeToString(hash));
                saveData();

                send(player, NamedTextColor.GREEN, "Регистрация прошла успешно!");
                authenticate(player);
            });
        });
    }

    private void handleLogin(Player player, String[] args) {
        UUID id = player.getUniqueId();
        if (!isRegistered(id)) {
            send(player, NamedTextColor.RED, "Вы не зарегистрированы. Напишите /register (пароль)");
            return;
        }
        if (args.length != 1) {
            send(player, NamedTextColor.RED, "Используйте: /login (пароль)");
            return;
        }
        String password = args[0];
        String path = "players." + id;
        String saltB64 = data.getString(path + ".salt", "");
        String hashB64 = data.getString(path + ".hash", "");
        if (!busy.add(id)) {
            return;
        }

        getServer().getScheduler().runTaskAsynchronously(this, () -> {
            boolean ok;
            try {
                byte[] expected = Base64.getDecoder().decode(hashB64);
                byte[] actual = hash(password, Base64.getDecoder().decode(saltB64));
                ok = MessageDigest.isEqual(expected, actual);
            } catch (RuntimeException ex) {
                getLogger().severe("Ошибка проверки пароля: " + ex);
                ok = false;
            }
            boolean success = ok;
            getServer().getScheduler().runTask(this, () -> {
                busy.remove(id);
                if (!player.isOnline() || !unauthenticated.contains(id)) {
                    return;
                }
                if (success) {
                    send(player, NamedTextColor.GREEN, "Вы успешно вошли!");
                    authenticate(player);
                    return;
                }
                int used = attempts.merge(id, 1, Integer::sum);
                if (used >= MAX_LOGIN_ATTEMPTS) {
                    player.kick(Component.text("Слишком много неверных попыток входа.", NamedTextColor.RED));
                } else {
                    send(player, NamedTextColor.RED, "Неверный пароль. Осталось попыток: "
                            + (MAX_LOGIN_ATTEMPTS - used));
                }
            });
        });
    }

    // ------------------------------------------------------------------ listeners

    @EventHandler
    public void onJoin(PlayerJoinEvent event) {
        startAuth(event.getPlayer());
    }

    @EventHandler
    public void onQuit(PlayerQuitEvent event) {
        Player player = event.getPlayer();
        UUID id = player.getUniqueId();
        boolean wasUnauthenticated = unauthenticated.remove(id);
        cancelTimer(id);
        attempts.remove(id);
        busy.remove(id);
        if (wasUnauthenticated) {
            // Не оставляем игрока сохранённым в мире-бездне и возвращаем ему режим игры.
            restoreAndLeaveVoid(player);
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onChat(AsyncChatEvent event) {
        Player player = event.getPlayer();
        if (unauthenticated.contains(player.getUniqueId())) {
            event.setCancelled(true);
            send(player, NamedTextColor.RED, "Сначала авторизуйтесь: /register (пароль) или /login (пароль)");
            return;
        }
        // Неавторизованные игроки не видят чат.
        event.viewers().removeIf(v -> v instanceof Player p && unauthenticated.contains(p.getUniqueId()));
    }

    @EventHandler(priority = EventPriority.LOWEST)
    public void onCommandPreprocess(PlayerCommandPreprocessEvent event) {
        Player player = event.getPlayer();
        if (!unauthenticated.contains(player.getUniqueId())) {
            return;
        }
        String label = event.getMessage().substring(1).split(" ", 2)[0].toLowerCase(Locale.ROOT);
        int colon = label.indexOf(':');
        if (colon >= 0) {
            label = label.substring(colon + 1);
        }
        if (!ALLOWED_COMMANDS.contains(label)) {
            event.setCancelled(true);
            send(player, NamedTextColor.RED, "Сначала авторизуйтесь: /register (пароль) или /login (пароль)");
        }
    }

    @EventHandler(priority = EventPriority.HIGHEST)
    public void onDamage(EntityDamageEvent event) {
        if (event.getEntity() instanceof Player player && unauthenticated.contains(player.getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onInteract(PlayerInteractEvent event) {
        if (unauthenticated.contains(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onDrop(PlayerDropItemEvent event) {
        if (unauthenticated.contains(event.getPlayer().getUniqueId())) {
            event.setCancelled(true);
        }
    }

    @EventHandler
    public void onPickup(EntityPickupItemEvent event) {
        if (event.getEntity() instanceof Player player && unauthenticated.contains(player.getUniqueId())) {
            event.setCancelled(true);
        }
    }

    // ------------------------------------------------------------------ helpers

    private boolean isRegistered(UUID id) {
        return data.contains("players." + id + ".hash");
    }

    private void saveData() {
        try {
            data.save(dataFile);
        } catch (IOException ex) {
            getLogger().severe("Не удалось сохранить players.yml: " + ex);
        }
    }

    private static void send(Player player, NamedTextColor color, String text) {
        player.sendMessage(Component.text(text, color));
    }

    private static byte[] hash(String password, byte[] salt) {
        PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt, PBKDF2_ITERATIONS, 256);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException ex) {
            throw new IllegalStateException(ex);
        } finally {
            spec.clearPassword();
        }
    }

    /** Пустой генератор: мир без единого блока — сплошная бездна. */
    private static final class VoidGenerator extends ChunkGenerator {
        @Override
        public Location getFixedSpawnLocation(World world, Random random) {
            return new Location(world, 0.5, VOID_SPAWN_Y, 0.5);
        }
    }
}
