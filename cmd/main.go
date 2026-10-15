// Command manager runs the Malcolm operator.
package main

import (
	"crypto/tls"
	"flag"
	"os"
	"strings"

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
	"sigs.k8s.io/controller-runtime/pkg/metrics/filters"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	malcolmv1 "github.com/idaholab/malcolm-operator/api/v1alpha1"
	"github.com/idaholab/malcolm-operator/internal/controller"
)

var (
	scheme   = runtime.NewScheme()
	setupLog = ctrl.Log.WithName("setup")
)

func init() {
	utilruntime.Must(clientgoscheme.AddToScheme(scheme))
	utilruntime.Must(malcolmv1.AddToScheme(scheme))
}

func main() {
	var (
		metricsAddr      string
		probeAddr        string
		enableLeaderElec bool
		secureMetrics    bool
		enableHTTP2      bool
		watchNamespaces  string
	)
	flag.StringVar(&metricsAddr, "metrics-bind-address", "0",
		"The address the metrics endpoint binds to. Use :8443 for HTTPS or :8080 for HTTP, or 0 to disable.")
	flag.StringVar(&probeAddr, "health-probe-bind-address", ":8081", "The address the probe endpoint binds to.")
	flag.BoolVar(&enableLeaderElec, "leader-elect", false,
		"Enable leader election to ensure only one active controller manager.")
	flag.BoolVar(&secureMetrics, "metrics-secure", true,
		"Serve metrics over HTTPS with authentication and authorization.")
	flag.BoolVar(&enableHTTP2, "enable-http2", false,
		"Enable HTTP/2 for the metrics server (disabled by default due to HTTP/2 rapid-reset CVEs).")
	flag.StringVar(&watchNamespaces, "watch-namespaces", os.Getenv("WATCH_NAMESPACES"),
		"Comma-separated namespaces to watch for Malcolm resources (default: all namespaces).")
	opts := zap.Options{Development: false}
	opts.BindFlags(flag.CommandLine)
	flag.Parse()
	ctrl.SetLogger(zap.New(zap.UseFlagOptions(&opts)))

	var tlsOpts []func(*tls.Config)
	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, func(c *tls.Config) { c.NextProtos = []string{"http/1.1"} })
	}

	metricsOpts := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: secureMetrics,
		TLSOpts:       tlsOpts,
	}
	if secureMetrics {
		metricsOpts.FilterProvider = filters.WithAuthenticationAndAuthorization
	}

	cacheOpts := cache.Options{}
	if watchNamespaces != "" {
		cacheOpts.DefaultNamespaces = map[string]cache.Config{}
		for _, ns := range strings.Split(watchNamespaces, ",") {
			if ns = strings.TrimSpace(ns); ns != "" {
				cacheOpts.DefaultNamespaces[ns] = cache.Config{}
			}
		}
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsOpts,
		WebhookServer:          webhook.NewServer(webhook.Options{TLSOpts: tlsOpts}),
		HealthProbeBindAddress: probeAddr,
		LeaderElection:         enableLeaderElec,
		LeaderElectionID:       "malcolm-operator.malcolm.idaholab.github.io",
		Cache:                  cacheOpts,
	})
	if err != nil {
		setupLog.Error(err, "unable to create manager")
		os.Exit(1)
	}

	if err := (&controller.MalcolmReconciler{
		Client:    mgr.GetClient(),
		APIReader: mgr.GetAPIReader(),
		Scheme:    mgr.GetScheme(),
	}).SetupWithManager(mgr); err != nil {
		setupLog.Error(err, "unable to create controller", "controller", "Malcolm")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up health check")
		os.Exit(1)
	}
	if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
		setupLog.Error(err, "unable to set up ready check")
		os.Exit(1)
	}

	setupLog.Info("starting manager")
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		setupLog.Error(err, "problem running manager")
		os.Exit(1)
	}
}
