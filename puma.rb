max_threads_count = ENV.fetch("RAILS_MAX_THREADS") { 5 }
min_threads_count = ENV.fetch("RAILS_MIN_THREADS") { max_threads_count }
threads min_threads_count, max_threads_count
pidfile ENV.fetch("PIDFILE") { "./server.pid" }

port 8080

app_root = File.expand_path("..", __dir__)
pidfile "#{app_root}/puma.pid"
state_path "#{app_root}/puma.state"
threads 0, 16

bind "unix://#{app_root}/puma.sock"
activate_control_app
