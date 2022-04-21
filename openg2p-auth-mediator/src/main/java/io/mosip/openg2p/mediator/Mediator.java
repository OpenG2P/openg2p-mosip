package io.mosip.openg2p.mediator;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication(scanBasePackages = { "io.mosip.openg2p.mediator.*" })
public class Mediator {
	public static void main(String[] args){
	  SpringApplication.run(Mediator.class, args);
	}
}
